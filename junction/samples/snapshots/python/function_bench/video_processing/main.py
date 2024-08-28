from time import time
import json
import os
import cv2


def video_processing(file_path):
    output_file_path = '/tmp/output-' + os.path.basename(file_path)
    video = cv2.VideoCapture(file_path)

    width = int(video.get(3))
    height = int(video.get(4))

    fourcc = cv2.VideoWriter_fourcc(*'XVID')
    out = cv2.VideoWriter(output_file_path, fourcc, 20.0, (width, height))

    start = time()
    while (video.isOpened()):
        ret, frame = video.read()

        if ret:
            gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            # NOTE: junction fails here with permission denied
            im = cv2.imwrite('/tmp/frame.jpg', gray_frame)
            gray_frame = cv2.imread('/tmp/frame.jpg')
            out.write(gray_frame)
        else:
            break

    latency = time() - start

    video.release()
    out.release()
    return latency


def function_handler(request_json):
    input_path = request_json['input_path']
    latency = video_processing(input_path)

    return "latency : " + str(latency)
