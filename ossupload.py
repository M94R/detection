import oss2
import time
from threading import Thread
from datetime import datetime

class OSSManager:
    def __init__(self, access_key_id, access_key_secret, endpoint, bucket_name):
        auth = oss2.Auth(access_key_id, access_key_secret)
        self.bucket = oss2.Bucket(auth, endpoint, bucket_name)

    def upload_file(self, object_name, local_file_path):
        self.bucket.put_object_from_file(object_name, local_file_path)

access_key_id = 'LTAI5tLiQbsn4XCY2z1mtCCr'
access_key_secret = '3rbAzVTtqsz9dfDs15M2JM3fTKhpS7'
endpoint = 'oss-cn-beijing.aliyuncs.com'
bucket_name = 'networkassessment'

oss_manager = OSSManager(access_key_id, access_key_secret, endpoint, bucket_name)
file_path = '/home/songxin/detection/'
file_names = ['cpu_log.txt', 'networks_log.txt', 'process_log.txt']

def attack_upload(file_path, file_name, target_path):
    upload_path = file_path + file_name
    a_oss_path = target_path + file_name
    oss_manager.upload_file(a_oss_path, upload_path)

# 定义上传函数的线程
def upload_threads(target_path):
    threads = []
    for file_name in file_names:
        t = Thread(target=attack_upload, args=(file_path, file_name, target_path))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()

# 循环上传文件
while True:
    current_time = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    new_folder_name = '192.168.84.162/' + current_time + '/'
    target_path = 'node-resource/' + new_folder_name
    upload_threads(target_path)
    time.sleep(300)  # 等待5分钟

