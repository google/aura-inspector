# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import requests
import re, json
import traceback
from colored_logger import logger
from urllib.parse import urlparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from http.cookies import SimpleCookie

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.16; rv:85.0) Gecko/20100101 Firefox/85.0'
AURA_ENDPOINTS = ['/s/sfsites/aura','/s/aura','/aura','/sfsites/aura']

class AuraActionHelper:
	def build_action(act_id, descriptor, params={}):
		return {
			'id':act_id,
			'descriptor':descriptor,
			'callingDescriptor':'UNKNOWN',
			'params':params
		}

	def build_context(fwuid, app, loaded):
		return json.dumps({
			"mode":"PROD",
			"fwuid":fwuid,
			"app":app,
			"loaded":loaded,
			"dn":[],
			"globals":{},
			"uad":False
		})

	def get_dummy_action():
		return AuraActionHelper.build_action(
			'242;a',
			'serviceComponent://ui.force.components.controllers.relatedList.RelatedListContainerDataProviderController/ACTION$getRecords',
			{"recordId":"Foobar"}
		)

	def get_dummy_context():
		return AuraActionHelper.build_context(
			"INVALID",
			"siteforce:loginApp2",
			{"APPLICATION@markup://siteforce:loginApp2":"siteforce:loginApp2"}
		)

class AuraActionResponse:
	def __init__(self, json_action):
		self.json_action = json_action
		self.id = None
		self.state = None
		self.return_value = None
		self.error_message = None
		self.parse_action_response()

	def parse_action_response(self):
		self.state = self.json_action['state']
		self.id = self.json_action['id']
		if self.is_success():
			self.return_value = self.json_action['returnValue']
		if self.is_error():
			error = self.json_action["error"][0]
			if 'event' in error:
				error_values = self.json_action["error"][0]["event"]["attributes"]["values"]
				if 'error' in error_values:
					self.error_message = error_values['error']['message']
				elif 'message' in error_values:
					self.error_message = error_values['message']
			elif 'message' in error:
				self.error_message = self.json_action["error"][0]["message"]

	def is_success(self):
		return self.state == 'SUCCESS'

	def is_error(self):
		return self.state == 'ERROR'

class AuraResponse:

	def __init__(self, response):
		self.response = response
		self.json_response = None
		self.actions_responses = []
		self.parse_response()

	def parse_response(self):
		if self.is_valid():
			self.json_response = self.response.json()
			for action in self.json_response.get('actions',[]):
				self.actions_responses.append(AuraActionResponse(action))
		else:
			logger.verbose(f"Invalid JSON response: {self.response.text}")

	def is_valid(self):
		try:
			self.response.json()
			return True
		except:
			False

class AuraResponses:

    def __init__(self, aura_responses):
        self.aura_responses = aura_responses
        self.actions_responses = []
        self.aggregate_action_responses()

    def aggregate_action_responses(self):
        #Make one list of action responses to aggregate bulked requests
        for aura_response in self.aura_responses:
            self.actions_responses += aura_response.actions_responses

class AuraHelper:

	def __init__(self, url, cookies, proxy, insecure, app, aura, context, token):

		self.url = url.rstrip('/')
		self.aura_token = 'undefined' if not token else token
		self.headers = {'User-Agent': USER_AGENT, 'Accept':'application/json'}
		self.session = requests.session()

		# If SID is not supplied, test guest access
		if cookies is None:
			logger.error('Cookies not supplied. This will only perform unauthenticated checks')
		else:
			parsed_cookies = SimpleCookie(cookies)
			for key, value in parsed_cookies.items():
				self.session.cookies.set(key, value)
			if self.session.cookies.get("sid") == None:
				logger.error("Cookies supplied but session cookie - SID not provided. This will only perform unauthenticated checks")

		self.objects = {}
		self.fwuid = None
		self.app = None
		self.csp_trusted = []
		self.gql_enabled = False
		self.session.verify = False if insecure else True
		self.session.proxies.update({} if not proxy else {'http':proxy, 'https':proxy})
   
		# Find the aura endpoint
		self.aura_endpoint = self.get_aura_endpoint() if not aura else aura
		logger.info(f'Using aura endpoint: {self.url}{self.aura_endpoint}')
		# Retrieve app information
		self.app = self.get_app() if not app else f"{self.url}/{app.lstrip('/')}"
		logger.info(f'Using app: {self.app}')
		# Retrieve the context including fwuid
		self.context = self.get_context() if not context else context
		logger.debug(f'Using context: {self.context}')
		# Finally get aura token
		self.aura_token = self.get_aura_token() if not token else token
		logger.debug(f'Using token: {self.aura_token}')

	def build_post_body(self, actions=[], dummy=False):
		message = {
			'message': json.dumps({'actions':[AuraActionHelper.get_dummy_action()]}) if dummy else json.dumps({'actions':actions}),
			'aura.context': AuraActionHelper.get_dummy_context() if dummy else self.context,
			'aura.pageURI': 'unknown',
			'aura.token': self.aura_token
		}
		return message

	def send_aura_bulk(self, actions=[], chunk_size=100, dummy=False):
		chunk_size = min(chunk_size,100) #Max is 100
		actions = [actions] if not isinstance(actions, list) else actions #Make it work with both lists and single actions
		actions_chunks = [actions[i:i+chunk_size] for i in range(0, len(actions), chunk_size)] #Split in chunks of 100
		aura_responses = []
		for i in range(len(actions_chunks)):
			chunk = actions_chunks[i]
			post_body = self.build_post_body(chunk)
			if len(chunk) > 1:
				logger.verbose(f"Sending bulk aura actions from {i*chunk_size} to {i*chunk_size+len(chunk)}")
			try:
				response = self.session.post(url=f"{self.url}{self.aura_endpoint}", headers=self.headers, data=post_body, timeout=90)
				aura_response = AuraResponse(response)
				aura_responses.append(aura_response)
			except requests.exceptions.SSLError as e:
				logger.error("Error when sending aura request, try using parameter -k to ignore invalid certificates")
				logger.debug(traceback.format_exc())
			except requests.exceptions.ReadTimeout as e:
				if chunk_size > 1:
					logger.error("Timeout when sending aura request, re-attempting to send the chunk slowly and without bulking...")
					aura_responses += self.send_aura_bulk(chunk, chunk_size=1).aura_responses
		return AuraResponses(aura_responses)

	def get_aura_endpoint(self):
		post_body = self.build_post_body(dummy=True)
		for endpoint in AURA_ENDPOINTS:
			try:
				post_request = self.session.post(f"{self.url}{endpoint}", allow_redirects=False, headers=self.headers, data=post_body)
				if 'markup://' in post_request.text:
					return endpoint
				elif post_request.status_code == 301 and post_request.headers.get('Location'):
					redir_url = post_request.headers.get('Location')
					post_request = self.session.post(redir_url, allow_redirects=False, headers=self.headers, data=post_body)
					if 'markup://' in post_request.text:
						return urlparse(redir_url).path
			except requests.exceptions.SSLError:
				logger.error("Error when trying to retrieve aura endpoint, try using parameter -k to ignore invalid certificates")
			except requests.exceptions.ConnectionError:
				logger.error("Cannot reach the target URL, aborting...")
				logger.debug(traceback.format_exc())
				exit()
			except:
				logger.error("Error when trying to retrieve aura endpoint")
				logger.debug(traceback.format_exc())
				pass
		#If we get out of the loop we did not find it
		logger.critical('Could not identify aura endpoint.')
		exit()

	def get_context(self):
		response_body = self.session.get(self.app, allow_redirects=True, headers=self.headers)
		aura_encoded = re.search(r'\/s\/sfsites\/l\/([^\/]+fwuid[^\/]+)', response_body.text)
		context = AuraActionHelper.get_dummy_context()
		if aura_encoded is None:
			if ("window.location.href ='%s" % self.url) in response_body.text:
				location_url = re.search(r'window.location.href =\'([^\']+)', response_body.text)
				url = location_url.group(1)
				try:
					response_body = self.session.get(url, allow_redirects=True, headers=self.headers)
				except Exception as e:
					logger.error("Failed to access the redirect url")
					raise
		fwuid = re.search(r'"fwuid":"([^"]+)', response_body.text)
		markup = re.search(r'"(APPLICATION@markup[^"]+)":"([^"]+)"', response_body.text)
		app = re.search(r'"app":"([^"]+)', response_body.text)
		if fwuid is None:
			post_body = self.build_post_body(dummy=True)
			retry_resp = self.session.post(f'{self.url}{self.aura_endpoint}', data=post_body, allow_redirects=True, headers=self.headers)
			resp_data = retry_resp.text
			fwuid_pattern = "Expected:(.*?) Actual"
			fwuid = re.search(fwuid_pattern, resp_data)

			if 'markup://aura:invalidSession' in resp_data:
				logger.critical('Invalid session when trying to get context, guest access might be disabled, aborting')
				exit()
			elif fwuid is None:
				json_resp_data = json.loads(resp_data)
				if 'context' in json_resp_data:
					fwuid = json_resp_data['context']['fwuid']
				else:
					logger.critical('No context found in response, aborting')
					logger.debug(json_resp_data)
					exit()
			else:
				fwuid = fwuid.group(1).strip()
			app_data = 'siteforce:loginApp2'
			context = AuraActionHelper.build_context(fwuid,app_data,{f"APPLICATION@markup://{app_data}":app_data})
		else:
			context = AuraActionHelper.build_context(fwuid.group(1),app.group(1),{f"{markup.group(1)}":f"{markup.group(2)}"})
   
		return context


	def get_aura_token(self):
		logger.verbose('Retrieving aura token')
		response = self.session.get(f"{self.app}", allow_redirects=True, headers=self.headers)

		aura_token_pattern = r'eyJub[^";]+'
		aura_token = 'null'
		if aura_token_search := re.search(aura_token_pattern, response.text):
			aura_token = aura_token_search.group(0)
			logger.verbose(f'Found aura token in page: {aura_token}')
		elif 'set-cookie' in response.headers:
			if aura_token_search := re.search(aura_token_pattern, response.headers['set-cookie']):
				aura_token = aura_token_search.group(0)
				logger.verbose(f'Found aura token in cookie: {aura_token}')
		else:
			logger.error(f'Aura token not found (probably because SID cookie was not supplied), using null token')
   
		return aura_token


	def get_app(self):
		logger.verbose('Retrieving app')
		for endpoint in AURA_ENDPOINTS:
			if endpoint in self.aura_endpoint:
				return f'{self.url}{self.aura_endpoint.replace(endpoint,"")}/s'
		#If we got out of the loop we did not find it
		logger.error('App not found, using default app /s')
		return self.url + '/s'


	def get_objects(self):
		logger.verbose('Attempting to retrieve all objects and CSP trusted sites')
		action = AuraActionHelper.build_action("1;a","aura://HostConfigController/ACTION$getConfigData")
		objects = []
		try:
			action_response = self.send_aura_bulk(action).actions_responses[0]
			self.csp_trusted = action_response.return_value['cspTrustedSites']
			objects = list(action_response.return_value['apiNamesToKeyPrefixes'].keys())
			logger.info(f'Found {len(objects)} objects')
		except:
			logger.error("Error while retrieving objects and CSP trusted sites")
			logger.debug(traceback.format_exc())

		return objects

	def get_records(self, objects):

		results = {}
		actions = []
		for object_name in objects:
			params = {
				"entityNameOrId":object_name,
				"layoutType":"COMPACT",
				"pageSize":1,
				"currentPage":1,
				"useTimeout":False,
				"getCount":True,
				"enableRowActions":False
			}
			action = AuraActionHelper.build_action(
				object_name,
				"serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems",
				params
			)

			actions.append(action)

		logger.info(f"Attempting to retrieve information for {len(objects)} objects")
		actions_responses = self.send_aura_bulk(actions).actions_responses
		for action_response in actions_responses:
			object_name = action_response.id
			if action_response.is_success():
				total_count = action_response.return_value.get('totalCount') or 0
				results[object_name] = {'records':[],'total_count': total_count}
			elif action_response.is_error():
				logger.debug(f'Could not retrieve records for {object_name}: {action_response.error_message}')

		logger.info(f'Retrieved information for {len(results)} objects')
		return results

	def get_records_ui_list(self, objects):

		results = set()
		objects_with_views = {}
		actions = []
		for i in range(len(objects)):

			object_name = objects[i]

			action = AuraActionHelper.build_action(
				object_name,
				"serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider.ListViewPickerDataProviderController/ACTION$getInitialListViews",
				{
					"scope":object_name,
					"maxMruResults":10,
					"maxAllResults":20
				}
			)
			actions.append(action)

		logger.verbose(f"Attempting to retrieve UI lists for {len(objects)} objects")
		actions_responses = self.send_aura_bulk(actions).actions_responses
		for action_response in actions_responses:

			object_name = action_response.id
			try:
				if action_response.is_success() and len(action_response.return_value['listViews']) > 0:
					objects_with_views[object_name] = action_response
					# results.append(f'{self.app}/recordlist/{object_name}/Default')
				elif action_response.is_error():
					logger.debug(f'Error while retrieving UI lists: {action_response.error_message}')
			except:
				logger.error(f'Unhandled error while retrieving UI record lists for object {object_name}')
				logger.debug(traceback.format_exc())

		if len(objects_with_views) > 0:
			logger.info("Checking accessible views for each object")
			
			actions = []

			# Build action list
			for obj in objects_with_views:
				
				try:
					for filter in objects_with_views[obj].return_value['listViews']:
						action = AuraActionHelper.build_action(
							f'{obj};{filter["name"]}',
							"serviceComponent://ui.force.components.controllers.lists.listViewDataManager.ListViewDataManagerController/ACTION$getItems",
							{
								"filterName":filter['name'],
								"entityName":obj,
								"pageSize":50,
								"layoutType":"LIST",
								"getCount":True,
								"enableRowActions":False,
								"offset":0
							}
						)

						actions.append(action)
			
				except:
					logger.error(f'Unhandled error while retrieving UI record list for object {object_name}')

			actions_responses = self.send_aura_bulk(actions).actions_responses

			for action_response in actions_responses:
				try:
					object_name,filter_name = action_response.id.split(";")
					if action_response.is_success() and len(action_response.return_value['recordIdActionsList']) > 0:
						logger.verbose(f'Identified accessible record list for {object_name} for filter {filter_name}')
						results.add(f'{self.app}/recordlist/{object_name}/Default')
				except:
					logger.debug(f'Error while retrieveing parsing UI list response')

		else:
			logger.info(f'No UI record lists for the targeted objects')

		if len(results) > 0:
			logger.warning(f'Found {len(results)} UI record lists for the targeted objects, please check these URLs manually as they could display sensitive records')
		
		return list(results)

	def get_object_home_urls(self):

		logger.verbose('Attempting to retrieve object home URLs')
		action = AuraActionHelper.build_action(
			"17;a",
			"serviceComponent://ui.communities.components.aura.components.communitySetup.cmc.CMCAppController/ACTION$getAppBootstrapData",
		)

		results = []
		try:
			action_response = self.send_aura_bulk(action).actions_responses[0]
			if action_response.is_success():
				results = action_response.json_action['components'][0]['model']['apiNameToObjectHomeUrls']
				logger.warning(f'Found {len(results)} object home URLs, please check these URLs manually as they could contain sensitive panels')
			elif action_response.is_error():
				logger.verbose(f'Could not retrieve object home URLs: {action_response.error_message}')
		except:
			logger.error('Error while retrieving object home URLs')
			logger.debug(traceback.format_exc())

		return results

	def check_self_registration_enabled(self):

		logger.verbose('Checking if self-registration is enabled')
		actions = [
	  		AuraActionHelper.build_action("1", "apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled"),
			AuraActionHelper.build_action("2", "apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl")
		]

		try:
			actions_responses = self.send_aura_bulk(actions).actions_responses
			is_enabled_response = actions_responses[0]
			url_response = actions_responses[1]
			if is_enabled_response.is_success() and is_enabled_response.return_value:
				selfreg_url = url_response.return_value
				logger.warning(f'Self-registration is enabled and URL is {selfreg_url}')
				return selfreg_url
			else:
				logger.info(f'Self-registration is not enabled')
		except:
			logger.error('Error while checking for self-registration, if you are using a SID cookie it is usually normal behavior')
			logger.debug(traceback.format_exc())

		return None

	def check_graphql_enabled(self):

		logger.verbose('Checking if GraphQL queries can be used')
		action = AuraActionHelper.build_action(
			"GraphQL",
			"aura://RecordUiController/ACTION$executeGraphQL",
			{
				"queryInput":
				{
					"operationName":"getUsersCount",
					"query":"query getUsersCount{uiapi{query{User{totalCount}}}}",
					"variables":{}
				}
			}
		)

		try:
			action_response = self.send_aura_bulk(action).actions_responses[0]
			if action_response.is_success():
				return_value = action_response.return_value
				if 'errors' in return_value and len(return_value['errors']) > 0:
					logger.debug(f"GraphQL is enabled, but it does not seem like the user can use it, error message: {return_value['errors']['message']}")
				else:
					logger.verbose("GraphQL is enabled, will try to prioritize it's use")
					self.gql_enabled = True
			elif action_response.is_error():
				try:
					logger.verbose(f"GraphQL is not available: {action_response.error_message}")
				except:
					logger.verbose('GraphQL is not available')
			else:
				raise Exception(f'Unknown error when checking if GraphQL is enabled')
		except Exception as e:
			logger.error('Error while checking if GraphQL is enabled')
			logger.debug(traceback.format_exc())

	def get_graphql_fields_for_objects(self, objects):
		logger.verbose("Retrieving field names for objects using GraphQL")
		banned_fields = ["CloneSourceId"] #Not handled properly by the tool (yet?)
		banned_types = ["ADDRESS","ANYTYPE","COMPLEXVALUE"] #Not handled properly by the tool (yet?)
		object_fields_map = {}

		# GraphQL apiNames is limited to 100 entries
		for i in range(0, len(objects), 100):
			batch = objects[i:i+100]

			#Formatting as follow objectInfos(apiNames:User,Account) etc...
			formatted_object_names = json.dumps(batch,separators=(',', ':'))
			action = AuraActionHelper.build_action(
				'1;fields',
				'aura://RecordUiController/ACTION$executeGraphQL',
				{
					'queryInput':{
						'operationName':'getFields',
						'query':'query getFields{uiapi{objectInfos(apiNames:%s){ApiName,fields{ApiName,dataType}}}}' % (formatted_object_names),
						'variables':{},
					}
				}
			)
			action_response = self.send_aura_bulk(action).actions_responses[0]
			if not action_response.is_success():
				logger.error('Error while retrieving field names with GraphQL')
				return None
			print(action_response.return_value)
			objects_infos = filter(None, action_response.return_value['data']['uiapi']['objectInfos'])
			object_fields_map = {x['ApiName']: [y['ApiName'] for y in x['fields'] if y['dataType'] not in banned_types and y['ApiName'] not in banned_fields] for x in objects_infos}
		return object_fields_map

	def get_object_count_graphql(self, objects, make_chunks=True):
		logger.verbose("Counting number of records for each objects using GraphQL")
		chunk_size = 10 if make_chunks else 1 #Can be chunk in block of 10 per action, so 10*100 objects in one aura request
		objects_chunks = [objects[i:i+chunk_size] for i in range(0, len(objects), chunk_size)]
		actions_responses = []
		for chunk in objects_chunks:
			#Formatting as follow: "User{totalCount}Account{totalCount}..."
			total_count_query = "".join([f"{object_name}{{totalCount}}" for object_name in chunk])
			action = AuraActionHelper.build_action(
				'1;a',
				'aura://RecordUiController/ACTION$executeGraphQL',
				{
					'queryInput':{
						'operationName':'getCount',
						'query':'query getCount{uiapi{query{%s}}}' % (total_count_query),
						'variables':{},
					}
				}
			)
			try:
				actions_responses += self.send_aura_bulk([action]).actions_responses
			except requests.exceptions.ReadTimeout:
				logger.error("Timeout when trying to count records, one object might have too many records, counting object records one by one...")
				for obj_name in chunk:
					action = AuraActionHelper.build_action(
						'1;a',
						'aura://RecordUiController/ACTION$executeGraphQL',
						{
							'queryInput':{
								'operationName':'getCount',
								'query':'query getCount{uiapi{query{%s{totalCount}}}}' % (obj_name),
								'variables':{},
							}
						}
					)
					try:
						actions_responses += self.send_aura_bulk([action], chunk_size=1).actions_responses
					except requests.exceptions.ReadTimeout:
						logger.error(f"Timeout when trying to count records of {obj_name}, might have too many records")
						object_count_map = {obj_name:-1}

		object_count_map = {}
		all_failed_chunks = []
		for action_response in actions_responses:
			#Error with graphql are not determined by aura state field
			str_response = json.dumps(action_response.return_value)
			if 'uiapi' in action_response.return_value['data']:
				query_response = action_response.return_value['data']['uiapi']['query']
				for obj_name in query_response.keys():
					if query_response[obj_name]:
						object_count_map[obj_name] = query_response[obj_name]['totalCount']
					elif query_response[obj_name] is None:
						for error in action_response.return_value['errors']:
							if 'OPERATION_TOO_LARGE' in error['message'] and len(error['paths']) == 3 and error['paths'][2] == obj_name:
								logger.verbose(f'{obj_name} caused OPERATION_TOO_LARGE, it likely has too many records, setting count at -1')
								object_count_map[obj_name] = -1
							else:
								logger.debug(f'Ignoring {obj_name} because of: {error["message"]}')
			elif 'ValidationError' in str_response:
				#One object likely cause an issue in the request, we need to send them individually
				if make_chunks:
					error_field_regex = r'FieldUndefined:[^\'"]+[\'"]([^\'"]+)[\'"]'
					if error_fields := re.findall(error_field_regex, str_response):
						failed_chunks = [chunk for chunk in objects_chunks for error_field in error_fields if error_field in chunk]
						for failed_chunk in failed_chunks:
							all_failed_chunks += failed_chunk
			else:
				logger.debug("Unhandled error when getting total count for objects with GraphQL: "+json.dumps(action_response.return_value))
		if all_failed_chunks:
			#Send the failed objects individually by calling the func again and not making chunks
			logger.verbose(f'Resending failed chunks while counting records with GraphQL: {all_failed_chunks}')
			failed_chunks_count_map = self.get_object_count_graphql(all_failed_chunks, make_chunks=False)
			object_count_map.update(failed_chunks_count_map)
		return object_count_map

	def get_records_graphql(self, objects, records_per_action=2000, fetch_all=True):
		results = {}

		#Retrieve field names for each object and validate that they can be accessed with uiapi
		object_fields_map = self.get_graphql_fields_for_objects(objects)
		uiapi_objects = list(object_fields_map.keys())
		logger.info(f"{len(uiapi_objects)} objects accessible with GraphQL through uiapi")

		logger.info("Hang tight - this may take a while")

		#Retrieve object counts for each object to only retrieve records for those
		object_count_map = self.get_object_count_graphql(uiapi_objects)
		objects_with_records = [object_name for object_name in object_count_map if object_count_map[object_name] != 0]
		results = {k: {'records': [], 'total_count': v} for k, v in object_count_map.items() if v != 0}
		logger.info(f"{len(objects_with_records)} objects with records for a total of {sum(object_count_map.values())} records")
		return results

	def get_custom_controllers(self):
		# Ignore query params
		parsed_url = urlparse(self.app)
		req_url = f'{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}'
		resp = self.session.get(req_url)
		response_text = resp.text
		custom_controllers = {}
		endpoint_pattern = r'src="([^"]*)"'
		auracmp_pattern = r'/auraCmdDef\?[^"\']+'
		custom_controller_pattern = r'apex://[a-zA-Z0-9_-]+/ACTION\$[a-zA-Z0-9_-]+'

		# Find all URLs using the regular expression pattern
		endpoints = re.findall(endpoint_pattern, response_text) + re.findall(auracmp_pattern, response_text)
		logger.verbose('Endpoints that could contain information about custom controllers discovered, analyzing them')
		logger.debug(endpoints)

		found = False
		for endpoint in endpoints:
			if not 'http:' in endpoint and not 'https:' in endpoint:
				endpoint_url = f'{parsed_url.scheme}://{parsed_url.netloc}{endpoint}'
			else:
				endpoint_url = endpoint

			try:
				resp = self.session.get(endpoint_url)
				response_text = resp.text
				endpoint_controllers = re.findall(custom_controller_pattern, response_text)
				if endpoint_controllers:
					custom_controllers[endpoint_url] = endpoint_controllers if endpoint_url not in custom_controllers else list(set(custom_controllers[endpoint_url] + endpoint_controllers))
			except:
				logger.debug(f'Error when processing URL {endpoint_url} during custom controllers check')

		if len(custom_controllers) == 0:
			logger.error('Did not find any custom controllers')
		else:
			logger.warning(f'Found {sum([len(v) for v in custom_controllers.values()])} custom controllers')

		return custom_controllers


	def build_soap_message(self, body):
		sid = self.session.cookies.get("sid")
		xml_header = '<?xml version="1.0" encoding="utf-8"?>'
		soap_env_header = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tns="http://soap.sforce.com/2006/04/metadata">'
		soap_session = f'<soapenv:Header><tns:SessionHeader><tns:sessionId>{sid}</tns:sessionId></tns:SessionHeader></soapenv:Header>'
		soap_env_footer = '</soapenv:Envelope>'
		return f'{xml_header}{soap_env_header}{soap_session}{body}{soap_env_footer}'


	def check_soap_api_enabled(self):
		logger.verbose('Checking if SOAP API is exposed (Require API enabled permission)')
		try:
			#Need to see if there is a way to get latest version
			soap_req = self.session.post(f'{self.url}/services/Soap/u/35.0', headers={'Content-Type':'text/xml', 'SOAPAction': 'Empty'})
			if soap_req.status_code == 500 and 'text/xml' in soap_req.headers['Content-Type']:
				logger.info('SOAP API seems to be enabled, may require username and password authentication')
			else:
				logger.info('SOAP API does not seem to be exposed')
		except:
			logger.error('Error while querying the SOAP API')
			logger.debug(traceback.format_exc())


	def check_rest_api_enabled(self):
		logger.verbose('Checking if REST API is exposed (Require API enabled permission)')
		latest_rest_url = None
		try:
			latest_rest_url_req = self.session.get(f'{self.url}/services/data')
			latest_rest_url = latest_rest_url_req.json()[-1]['url']
			logger.verbose(f'Checking REST url using URL: {self.url}{latest_rest_url}')
		except:
			logger.error('Error while retrieving REST URL for latest version')
			logger.debug(traceback.format_exc())
			return False
		headers = {'Authorization': f'Bearer {self.session.cookies.get("sid")}'}
		try:
			rest_req = self.session.get(f'{self.url}{latest_rest_url}', headers=headers)
			if rest_req.status_code == 200:
				logger.info(f'REST API is accessible with the provided SID: {self.session.cookies.get("sid")}')
				return True
			else:
				logger.info(f'REST API is not accessible using the provided SID: {self.session.cookies.get("sid")}')
				return False
		except:
			logger.debug(traceback.format_exc())
			logger.error('Error while querying the REST request for latest version')
		return False
