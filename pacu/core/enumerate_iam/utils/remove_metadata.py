def remove_metadata(boto_response):
    if isinstance(boto_response, dict):
        boto_response.pop('ResponseMetadata', None)

    return boto_response
