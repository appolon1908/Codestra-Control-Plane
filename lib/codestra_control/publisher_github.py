"""Dedicated GitHub App transport. Never falls back to gh/PAT/shared credentials.

jwt_provider is a privileged credential-custodian dependency; this module does
not provision keys or accept JWTs from publication requests. Installation tokens
are held in memory, restricted to one repository, and never logged or persisted.
"""
from datetime import datetime,timezone
from dataclasses import dataclass
import re
import json
from urllib.parse import urlencode
from urllib.request import Request,build_opener,HTTPRedirectHandler
from .publisher_adapter import require,PublicationDenied

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise PublicationDenied('API_REDIRECT_REFUSED')

def request_json(method,path,token,body=None):
    require(path.startswith('/') and not path.startswith('//') and '://' not in path,'UNTRUSTED_API_PATH')
    payload=None if body is None else json.dumps(body).encode()
    request=Request('https://api.github.com'+path,data=payload,method=method,
                    headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json',
                             'X-GitHub-Api-Version':'2022-11-28','Content-Type':'application/json','User-Agent':'codestra-authenticated-publisher'})
    try:
        with build_opener(NoRedirect()).open(request,timeout=15) as response:
            raw=response.read(4*1024*1024+1)
        require(len(raw)<=4*1024*1024,'API_RESPONSE_TOO_LARGE')
        return json.loads(raw)
    except Exception:
        # Do not propagate headers, token, request/body or remote response text.
        raise PublicationDenied('AUTHENTICATED_API_UNAVAILABLE') from None

@dataclass(frozen=True)
class ObservedPR:
    repository_id:int
    repository:str
    number:int
    source_ref:str
    target_ref:str
    source_sha:str
    target_base_sha:str
    @property
    def key(self):return (self.repository,self.source_ref,self.target_ref,self.source_sha,self.target_base_sha)

class GitHubAppClient:
    PERMISSIONS={'statuses':'write','checks':'read','contents':'read','pull_requests':'read','administration':'read','metadata':'read'}
    def __init__(self,jwt_provider,*,request=request_json,clock=lambda:datetime.now(timezone.utc)):
        self.jwt_provider,self.request,self.clock=jwt_provider,request,clock
        self._token=None;self._expires=None
    def assert_identity(self,authority,repository_id,now):
        self._token=None;self._expires=None
        jwt=self.jwt_provider()
        app=self.request('GET','/app',jwt)
        require(app['id']==authority.app_id,'APP_IDENTITY_MISMATCH')
        installation=self.request('GET',f'/app/installations/{authority.installation_id}',jwt)
        require(installation['id']==authority.installation_id and installation['app_id']==authority.app_id
                and installation['suspended_at'] is None,'INSTALLATION_REVOKED_OR_MISMATCHED')
        token=self.request('POST',f'/app/installations/{authority.installation_id}/access_tokens',jwt,
                           {'repository_ids':[repository_id],'permissions':dict(self.PERMISSIONS)})
        require(token['permissions']==self.PERMISSIONS and {v['id'] for v in token['repositories']}=={repository_id},'TOKEN_SCOPE_MISMATCH')
        expiry=datetime.fromisoformat(token['expires_at'].replace('Z','+00:00'))
        require(expiry.tzinfo is not None and expiry>now,'TOKEN_EXPIRED')
        require(type(token['token']) is str and bool(token['token']),'TOKEN_UNAVAILABLE')
        self._token=token['token'];self._expires=min(expiry,authority.expires_at)
    def authorize_readonly(self,app_id,installation_id,repository_id,now):
        """Independent materializer credentials cannot have write installation grants."""
        self._token=None;self._expires=None
        jwt=self.jwt_provider()
        require(self.request('GET','/app',jwt)['id']==app_id,'APP_IDENTITY_MISMATCH')
        installation=self.request('GET',f'/app/installations/{installation_id}',jwt)
        required={'metadata':'read','contents':'read','checks':'read'}
        require(installation['id']==installation_id and installation['app_id']==app_id and installation['suspended_at'] is None,'INSTALLATION_REVOKED_OR_MISMATCHED')
        require(required.items()<=installation['permissions'].items() and all(v=='read' for v in installation['permissions'].values()),'READONLY_INSTALLATION_REQUIRED')
        token=self.request('POST',f'/app/installations/{installation_id}/access_tokens',jwt,{'repository_ids':[repository_id],'permissions':required})
        require(token['permissions']==required and {v['id'] for v in token['repositories']}=={repository_id},'TOKEN_SCOPE_MISMATCH')
        expiry=datetime.fromisoformat(token['expires_at'].replace('Z','+00:00'))
        require(expiry.tzinfo is not None and expiry>now and type(token['token']) is str and bool(token['token']),'TOKEN_EXPIRED')
        self._token=token['token'];self._expires=expiry
    def inventory(self,app_id,installation_id,repositories):
        """Complete read-only discovery of the fixed approved source catalog.

        A separate read-only token cannot publish statuses. Real stable IDs are
        acquired from GitHub, never synthetic scope rows or configured guesses.
        """
        self._token=None;self._expires=None
        repositories=frozenset(repositories)
        require(bool(repositories) and all(v.startswith('appolon1908/') for v in repositories),'INVALID_INVENTORY_SCOPE')
        jwt=self.jwt_provider()
        require(self.request('GET','/app',jwt)['id']==app_id,'APP_IDENTITY_MISMATCH')
        installation=self.request('GET',f'/app/installations/{installation_id}',jwt)
        require(installation['id']==installation_id and installation['app_id']==app_id
                and installation['suspended_at'] is None and installation['account']['login']=='appolon1908','INVENTORY_INSTALLATION_MISMATCH')
        permissions={'metadata':'read','pull_requests':'read'}
        token=self.request('POST',f'/app/installations/{installation_id}/access_tokens',jwt,
                           {'repositories':sorted(v.split('/',1)[1] for v in repositories),'permissions':permissions})
        require(token['permissions']==permissions,'INVENTORY_TOKEN_SCOPE_MISMATCH')
        observed=token['repositories']
        require(len(observed)==len(repositories) and {v['full_name'] for v in observed}==repositories
                and all(type(v['id']) is int and v['id']>0 for v in observed)
                and len({v['id'] for v in observed})==len(observed),'INVENTORY_REPOSITORY_SCOPE_INCOMPLETE')
        expiry=datetime.fromisoformat(token['expires_at'].replace('Z','+00:00'))
        require(expiry.tzinfo is not None and expiry>self.clock() and type(token['token']) is str and bool(token['token']),'INVENTORY_TOKEN_UNAVAILABLE')
        self._token=token['token'];self._expires=expiry
        result=[]
        from .policy import valid_ref
        for repo in sorted(observed,key=lambda v:v['full_name']):
            for pr in self.pages(f'/repos/{repo["full_name"]}/pulls?state=open'):
                require(type(pr['number']) is int and pr['number']>0 and pr['state']=='open','INVALID_INVENTORY_PR')
                require(pr['base']['repo']['id']==repo['id'],'INVENTORY_REPOSITORY_MISMATCH')
                head,base=pr['head'],pr['base']
                require(all(valid_ref(v['ref']) and type(v['sha']) is str and re.fullmatch('[0-9a-f]{40}',v['sha']) for v in (head,base)),'INVALID_INVENTORY_BINDING')
                result.append(ObservedPR(repo['id'],repo['full_name'],pr['number'],head['ref'],base['ref'],head['sha'],base['sha']))
        return tuple(result)
    def _call(self,method,path,body=None):
        require(self._token is not None and self._expires>self.clock(),'APP_SESSION_UNAVAILABLE')
        return self.request(method,path,self._token,body)
    def get(self,path):return self._call('GET',path)
    def post(self,path,body):return self._call('POST',path,body)
    def pages(self,path,key=None):
        values=[];seen=set()
        for page in range(1,101):
            response=self.get(path+('&' if '?' in path else '?')+urlencode({'per_page':100,'page':page}))
            items=response if key is None else response[key]
            require(type(items) is list and len(items)<=100,'INVALID_API_PAGE')
            for item in items:
                require(type(item) is dict and type(item.get('id')) is int and item['id'] not in seen,'DUPLICATE_OR_INVALID_API_ITEM')
                seen.add(item['id']);values.append(item)
            if len(items)<100:return values
        raise PublicationDenied('API_PAGINATION_INCOMPLETE')
    def eligible_reviewer(self,repo,login):
        from urllib.parse import quote
        value=self.get(f'/repos/{repo}/collaborators/{quote(login,safe="")}/permission')
        return value['user']['login'].casefold()==login.casefold() and value['permission'] in ('write','maintain','admin')
    def threads_resolved(self,repo,number):
        owner,name=repo.split('/');cursor=None;seen=set()
        query='''query($owner:String!,$name:String!,$number:Int!,$after:String){repository(owner:$owner,name:$name){pullRequest(number:$number){reviewThreads(first:100,after:$after){nodes{id isResolved} pageInfo{hasNextPage endCursor}}}}}'''
        for _ in range(100):
            response=self.post('/graphql',{'query':query,'variables':{'owner':owner,'name':name,'number':number,'after':cursor}})
            require(not response.get('errors'),'THREAD_INVENTORY_FAILED')
            threads=response['data']['repository']['pullRequest']['reviewThreads']
            for node in threads['nodes']:
                require(node['id'] not in seen,'DUPLICATE_THREAD')
                seen.add(node['id'])
                if node['isResolved'] is not True:return False
            page=threads['pageInfo']
            if page['hasNextPage'] is False:return True
            require(type(page['endCursor']) is str and page['endCursor'] and page['endCursor']!=cursor,'THREAD_CURSOR_INVALID')
            cursor=page['endCursor']
        raise PublicationDenied('THREAD_INVENTORY_INCOMPLETE')
    def review_approved(self,repo,number):
        owner,name=repo.split('/')
        response=self.post('/graphql',{'query':'query($owner:String!,$name:String!,$number:Int!){repository(owner:$owner,name:$name){pullRequest(number:$number){reviewDecision}}}',
                                      'variables':{'owner':owner,'name':name,'number':number}})
        require(not response.get('errors'),'REVIEW_DECISION_UNAVAILABLE')
        return response['data']['repository']['pullRequest']['reviewDecision']=='APPROVED'
