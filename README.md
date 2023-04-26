# AVclass_virustotal_json2family_label
应用本项目可以实现vt得到的json文件，给malware打家族标签

step1:

  python vt2json.py -y 2020
  
 step2
 
   python json2lb.py -y 2020 -t vtjson
   
  step3
  
    cd avclassplusplus
    
    python avclass_labeler.py  -lb /malware_family_label/2016lb.json -hash sha256 >2016family.label
