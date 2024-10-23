
import uuid
import datetime

def profile_pictures(instance, filename):
    extension = filename.split('.')[-1]
    myuuid = uuid.uuid4()
    now = datetime.datetime.now() 
    date_time = now.strftime("%m/%d/%Y%H:%M:%S")
    new_filename = f"profile_picture/profile-{str(myuuid)}-{date_time}.{extension}"
    return new_filename