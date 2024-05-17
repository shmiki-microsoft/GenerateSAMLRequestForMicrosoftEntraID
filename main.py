import datetime
import zlib
import os
from base64 import b64encode
from urllib import parse


def build_saml_request(request_id, issuer):
    issue_instant=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds')
    return f'''
        <AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0"
            ID="_2257f698dd90d6f2948b32560245188332dcfc02bf" IssueInstant="{issue_instant}"
            Destination="https://login.microsoftonline.com/9b9df342-6ccb-43f9-b23f-28417a80cdaf/saml2"
            AssertionConsumerServiceURL="http://localhost:3000/assert"
            ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
            <saml:Issuer>saml2-js-local.shmiki.mikicorp.net</saml:Issuer>
            <NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent""/>
        </AuthnRequest>'''

def deflate(text):
    compressobj = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    return compressobj.compress(text.encode()) + compressobj.flush()

def get_saml_request_param(text):
    return parse.quote_plus(b64encode(deflate(text)))

saml_request_text = build_saml_request(
    request_id='id356a192b7913b04c54574d18c28d46e6395428ab', # 実際はハッシュとかにするのかな
    issuer=os.getenv('ISSUER') # Identifier (Entity ID)
)

print(f"https://login.microsoftonline.com/{os.getenv('TENANT_ID')}/saml2?SAMLRequest={get_saml_request_param(saml_request_text)}")
