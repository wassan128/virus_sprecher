# -*- coding: utf-8 -*-
import sys, string, base64, wave
import postfile, urllib, urllib2
import time
import json, os
import config

APIKEY = config.KEY

def post_bin(target):
	pf = postfile.postfile()
	host = "www.virustotal.com"
	selector = "https://www.virustotal.com/vtapi/v2/file/scan"
	fields = [("apikey", APIKEY)]
	file_to_send = open(target, "rb").read()
	files = [("file", target, file_to_send)]
	sent = pf.post_multipart(host, selector, fields, files)
	return sent

def read_report(sent):
	r = json.loads(sent)
	# DEBUG
	print r["scan_id"]
	while True:
		try:
			url = "https://www.virustotal.com/vtapi/v2/file/report"
			parameters = {
				"resource": r["scan_id"],
				"apikey": APIKEY
			}
			data = urllib.urlencode(parameters)
			req = urllib2.Request(url, data)
			res = urllib2.urlopen(req)
			j = json.loads(res.read())

			if j["response_code"] != -2:
				break
			else:
				# DEBUG
				print "still work...(response_code: %d)" % j["response_code"]
				time.sleep(30)
		except:
			pass
	return j

def voice(message):
	tts_url ="http://rospeex.ucri.jgn-x.jp/nauth_json/jsServices/VoiceTraSS"
	# command
	tts_command = {
		"method":"speak",
		"params": [
			"1.1",
			{
				"language": "ja",
				"text": message,
				"voiceType": "*",
				"audioType": "audio/x-wav"}]}

	obj_command = json.dumps(tts_command)     # string to json object
	req = urllib2.Request(tts_url, obj_command)
	received = urllib2.urlopen(req).read()    # get data from server
	 
	# extract wav file 
	obj_received = json.loads(received)
	tmp = obj_received['result']['audio'] # extract result->audio
	speech = base64.decodestring(tmp.encode('utf-8'))

	f = open ("out.wav",'wb')
	f.write(speech)
	f.close

def main():
	print "[Step1]: File submit..."
	target = sys.argv[1]
	sent = post_bin(target)
	print sent

	print "\n[Step2]: Waiting report..."
	result = read_report(sent)
	print "total: %d, positives: %d" % (result["total"], result["positives"])

	print "\n[Step3]: Check result..."
	try:
		if result["positives"] > 0:
			voice("%d個中%d個のウイルス対策ソフトがマルウェアと判定しました！" % (result["total"], result["positives"]))
			print "malware detected."
		else:
			voice("危険なソフトウェアではない可能性が高いと判定されました。")
			print "maybe it's benign."
	except:
		print "some error occurred."
		voice("エラーが発生してしまったようです。")

	os.system("aplay out.wav")

	print "complete."

if __name__ == "__main__":
	main()
