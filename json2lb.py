# -*- coding: utf-8 -*- 
# @Time : 2023/4/25 16:28 
# @Author : DirtyBoy 
# @File : json2lb.py
import json
import time
import os
import argparse


def summary_vt2json(sha256):
    lb_keys = ['sha1', 'av_labels', 'scan_date', 'first_seen', 'sha256', 'md5']
    dic = dict.fromkeys(lb_keys, 'null')
    data = load_json(
        '/home/lhd/Android_malware_detector_set/malware_family_label/json/vt_json/' + year + '/' + sha256 + '.json')
    dic['sha1'] = data['data']['attributes']['sha1']
    dic['sha256'] = data['data']['attributes']['sha256']
    dic['md5'] = data['data']['attributes']['md5']
    dic['first_seen'] = stamp2time(data['data']['attributes']['first_submission_date'])
    dic['scan_date'] = stamp2time(data['data']['attributes']['last_analysis_date'])
    av_label = []
    for item in data['data']['attributes']['last_analysis_results'].keys():
        if data['data']['attributes']['last_analysis_results'][item]['result']:
            tmp = []
            tmp.append(data['data']['attributes']['last_analysis_results'][item]['engine_name'])
            tmp.append(data['data']['attributes']['last_analysis_results'][item]['result'])
            av_label.append(tmp)

    dic['av_labels'] = av_label
    return dic


def summary_result2json(sha256):
    lb_keys = ['sha1', 'av_labels', 'scan_date', 'first_seen', 'sha256', 'md5']
    dic = dict.fromkeys(lb_keys, 'null')
    data = load_json(
        '/home/lhd/Android_malware_detector_set/malware_family_label/json/last_analysis_results/' + year + '/' + sha256 + '.json')
    dic['sha256'] = sha256
    av_label = []
    for item in data.keys():
        if data[item]['result']:
            tmp = []
            tmp.append(data[item]['engine_name'])
            tmp.append(data[item]['result'])
            av_label.append(tmp)
    dic['av_labels'] = av_label
    return dic


def stamp2time(timestamp):
    # eg.2008-06-26 07:26:48
    timeArray = time.localtime(timestamp)
    otherStyleTime = time.strftime("%Y-%m-%d %H:%M:%S", timeArray)
    return otherStyleTime


def load_json(json_path):
    with open(json_path, 'r') as fp:
        data = json.load(fp)
    return data


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-year', '-y', type=str, default='2015')
    parser.add_argument('-type', '-t', type=str, default='result', choices=['result', 'vtjson'])
    args = parser.parse_args()
    year = args.year
    type = args.type
    if type == 'vtjson':
        list = os.listdir('/home/lhd/Android_malware_detector_set/malware_family_label/json/vt_json/' + year)
        with open(year + 'lb.json', 'w') as f:
            for item in list:
                goal = json.dumps(summary_vt2json(os.path.splitext(item)[0]))
                f.write(goal)
                f.write('\n')
            f.close()
    else:
        list = os.listdir(
            '/home/lhd/Android_malware_detector_set/malware_family_label/json/last_analysis_results/' + year)
        with open(year + 'lb.json', 'w') as f:
            for item in list:
                goal = json.dumps(summary_result2json(os.path.splitext(item)[0]))
                f.write(goal)
                f.write('\n')
            f.close()
