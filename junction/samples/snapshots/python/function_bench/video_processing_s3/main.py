import cv2
from time import time
from minio import Minio
import urllib3

http = urllib3.PoolManager()
tmp = '/tmp/'

def video_processing(video_path):
    result_file_path = tmp + video_path

    video = cv2.VideoCapture(video_path)

    width = int(video.get(3))
    height = int(video.get(4))

    fourcc = cv2.VideoWriter_fourcc(*'XVID')
    out = cv2.VideoWriter(result_file_path, fourcc, 20.0, (width, height))

    while video.isOpened():
        ret, frame = video.read()

        if ret:
            gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            tmp_file_path = tmp+'tmp.jpg'
            cv2.imwrite(tmp_file_path, gray_frame)
            gray_frame = cv2.imread(tmp_file_path)
            out.write(gray_frame)
        else:
            break

    video.release()
    out.release()
    return

def function_handler(request_json):
    vid = request_json['vid']
    addr = request_json['minio_addr']

    path = f"{tmp}/{vid}"

    minio = Minio(addr,
                  http_client = http, # for some reason this makes urllib use ipv4 instead of unix sockets
                  access_key='minioadmin',
                  secret_key='minioadmin',
                  secure=False)

    start = time()

    minio.fget_object('bucket', vid, path)
    video_processing(path)

    latency = time() - start

    return {"latency": latency}

    
