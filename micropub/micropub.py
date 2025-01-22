class Client():
    def form_data_to_json(self, form_data):
        item = {
            "type": ["h-%s" % form_data.get("h", "entry")],
            "action": "",
            "properties": {}
        }

        return item



    def parse_post_request(self, data, body, content_type=None):
        if content_type is not None and content_type.lower() == "application/x-www-form-urlencoded":
            return self.parse_form_urlencoded_request(data)
        
        if content_type is not None and content_type.lower() == "application/json":
            return self.parse_json_request(body)
        
        try:
            return self.parse_form_urlencoded_request(data)
        except:
            return self.parse_json_request(body)
    
    def parse_form_urlencoded_request(self, data):
        post_type = data.get("h", "entry")
        action = data.get("action", "create")
        url = data.get("url", None)

        props = {}

        for key in data:
            if key == "access_token":
                continue

            if key.startswith("h"):
                continue

            if key.startswith("action"):
                continue

            if key.startswith("url"):
                continue

            props.update({ key: data["key"]})

        self.request = {
            "type": post_type,
            "action": action,
            "url": url,
            "props": props
        }

        return self.request
    
    def parse_json_request(self, body):
        pass

