def get_special_param(func, param):  
    FUNC_MAPPER = {
        'Bucket': get_bucket(),
        'Attribute': get_attribute(func)
    }      
    return FUNC_MAPPER.get(param, None)

def get_bucket():
    return 'alextestcloudtrailbucket'

def get_attribute(func):
    FUNC_ATTRIBUTES = {
        'reset_image_attribute': 'launchPermission',
        'reset_instance_attribute': 'kernel',
        'reset_snapshot_attribute': 'createVolumePermission',
        'describe_instance_attribute': 'kernel'
    }
    return FUNC_ATTRIBUTES.get(func, None)
