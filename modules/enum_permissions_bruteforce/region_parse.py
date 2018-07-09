from html.parser import HTMLParser
import urllib.request
import re

class RegionParser(HTMLParser):
	
    url = None
    last_tag = None
    service_data = {}
	
    def __init__(self, url = 'https://docs.aws.amazon.com/general/latest/gr/rande.html'):
        HTMLParser.__init__(self)
        self.last_tag = None
        self.url = url
        self.service_data = {}


    def handle_starttag(self, tag, attrs):
        if tag == 'h2' or tag == 'h3':
            id = attrs[0][1]
            #cut off '_region' for ids that contain it
            if '_region' in id:
                index = id.find('_region')
                id = attrs[0][1][:index]
            self.last_tag = id
            self.service_data[self.last_tag] = []

            
    def handle_data(self, data):
        if re.match(r'(\w+-)+\w+-\d$', data):
                self.service_data[self.last_tag].append(data)
    

    def handle_exceptions(self):
        self.service_data['all'] = [
            "us-east-2",
            "us-east-1",
            "us-west-1",
            "us-west-2",
            "ap-northeast-1",
            "ap-northeast-2",
            "ap-northeast-3",
            "ap-south-1",
            "ap-southeast-1",
            "ap-southeast-2",
            "ca-central-1",
            "cn-north-1",
            "cn-northwest-1",
            "eu-central-1",
            "eu-west-1",
            "eu-west-2",
            "eu-west-3",
            "sa-east-1",
            "us-gov-west-1"
        ]
        self.service_data['default'] = ['us-east-1']
        self.service_data['discovery'] = ['us-west-2']
        self.service_data['iot1click-projects'] = [
            'us-east-1',
            'us-east-2',
            'eu-central-1',
            'eu-west-1',
            'eu-west-2',
            'ap-northeast-1'
        ]
        self.service_data['iot1click-devices'] = ['us-west-2']
        self.service_data['neptune'] = [
            'ap-northeast-1',
            'ap-northeast-2',
            'ap-south-1',
            'ap-southeast-1',
            'ap-southeast-2',
            'ca-central-1',
            'eu-central-1',
            'eu-west-1',
            'eu-west-2',
            'eu-west-3',
            'sa-east-1',
            'us-east-1',
            'us-east-2',
            'us-west-1',
            'us-west-2'
        ]


    def parse(self):
        with urllib.request.urlopen(self.url) as response:
            self.feed(str(response.read()))
        self.handle_exceptions()
        return self.service_data
