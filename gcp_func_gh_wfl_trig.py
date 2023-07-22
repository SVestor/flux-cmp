import base64

from cloudevents.http import CloudEvent
import functions_framework
import requests
import os

# Triggered from a message on a Cloud Pub/Sub topic.
@functions_framework.cloud_event
def subscribe(cloud_event: CloudEvent) -> None:
    # Print out the data from Pub/Sub, to prove that it worked
    print(
        "secret update, " + base64.b64decode(cloud_event.data["message"]["data"]).decode() + "!"
    )
# Calling the github 'trigger_github_workflow' func after receiving a message in the topic
    trigger_github_workflow()
	
def trigger_github_workflow():
    github_api_url = 'https://api.github.com/repos/{owner}/{repo}/dispatches'

    owner = os.environ['OWNER'] 
    repo = os.environ['REPO'] 
    github_webhook_token = os.environ['GitHub_PAT'] 

    # Headers for a POST request to GitHub (token authentication)
    headers = {
        'Authorization': f'Bearer {github_webhook_token}',
        'Accept': 'application/vnd.github.everest-preview+json'
    }

    # The body of the POST request to generate the "repository_dispatch" event
    data = {
        'event_type': 'gcp_secret_changed',  # Event type
        'client_payload': {}  # You can pass additional data in the payload if needed
    }

    response = requests.post(github_api_url.format(owner=owner, repo=repo), json=data, headers=headers)

    if response.status_code == 204:
        print('GitHub Workflow triggered successfully')
    else:
        print('Error triggering GitHub Workflow')
