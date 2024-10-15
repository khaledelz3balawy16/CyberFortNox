from flask import Flask, request, render_template, redirect, flash, url_for, jsonify, make_response, abort, send_file, session
from werkzeug.utils import secure_filename
from datetime import datetime
import hashlib
import socket
import requests
import urllib
import time
import os
from config import Config
from models import db, User, Rule
from Scanner import Scanner
from Parser import Parser
from Fingerprinter import Fingerprinter
from Analyzer import Analyzer
from Tracker import Tracker
from Crypter import Crypter
from Unpacker import Unpacker
from HashIdentifier import HashIdentifier


# init Flask
app = Flask(__name__)
# config sqlite DB
app.config.from_object(Config)
# init DB
db.init_app(app)

@app.route('/', methods = ['GET'])
def main():
	is_sent = request.args.get("is_sent")
	return render_template("index.html", is_sent = is_sent)


@app.route('/about', methods = ['GET'])
def about():
	return render_template("about.html")


@app.route('/contact', methods = ['GET'])
def contact():
	return render_template("contact.html")


@app.route("/analysis", methods = ["GET"])
def analysis():
    # uploaded sample full path
	path_to_exe = "uploads/{}".format(request.args.get("filename"))
	# Init Scanner
	scanner = Scanner(path_to_exe)
	# Init Parser
	parser = Parser(path_to_exe)
	# Init Fingerprinter
	fingerprinter = Fingerprinter(path_to_exe)
    # Init Analyzer
	analyzer = Analyzer(path_to_exe)
    # Init Tracker
	tracker = Tracker(path_to_exe)
	# Init Crypter
	crypter = Crypter(path_to_exe)
	# get scan results
	scan_results = scanner.mal_sample_scan()
	# get nenefariousness score
	nefariousness_score = scanner.nefariousness_score
	# check for false-positice sample
	false_positive_sample = scanner.false_positive
	# get binary checksums
	md5_hash, sha1_hash, sha256_hash = parser.calculate_exe_checksums()
	# get binary architecture
	architecture = parser.get_exe_arch()
	# get binary type
	bin_type = parser.get_binary_type()
	# get file size
	bin_size = parser.get_file_size()
	# parse DOS header
	dos_header = parser.parse_exe_dos_header()
	# parse file header
	file_header = parser.parse_exe_file_header()
	# parse optional header
	optional_header = parser.parse_exe_optional_header()
	# parse section headers
	section_headers = parser.parse_exe_section_headers()
	# binary hex view
	hex_dump = parser.exe_hex_view()
	# extract dlls
	dlls = fingerprinter.extract_exe_dlls()
	# extract imported winapis
	winapis = fingerprinter.extract_exe_winapis()
	# extract exports
	exports = fingerprinter.extract_exe_exports()
	# extract IOCs (Indicators of Compromise)
	IOCs = fingerprinter.extract_exe_iocs()
	# detect injection techniques if any used
	injection_technique = analyzer.detect_injection_techniques(winapis)
    # detect Anti-debugging techniques if any used
	debug_flags_apis, exception_based_apis, timing_based_apis, interaction_based_apis, misc_apis = analyzer.detect_anti_debugging_techniques(winapis)
	# detect packers if any used
	packer = analyzer.detect_packers()
    # get sample C2s
	c2s_trackers = tracker.generate_c2s_heatmap()
	# analyze sample encryption and obfuscation techniques
	obf, enc = crypter.parse_binary_data()

	# show data
	return render_template("analysis.html",
		bin_name 				= path_to_exe.split("/")[-1],
		scan_results			= scan_results,
		nefariousness_score		= nefariousness_score,
		false_positive_sample	= false_positive_sample,
		md5_hash 				= md5_hash,
		sha1_hash 				= sha1_hash,
		sha256_hash 			= sha256_hash,
		bin_type 				= bin_type,
		architecture 			= architecture,
		bin_size 				= bin_size,
		dos_header 				= dos_header,
		file_header 			= file_header,
		optional_header 		= optional_header,
		section_headers 		= section_headers,
		hex_dump 				= hex_dump,
		dlls 					= dlls,
		winapis 				= winapis,
		exports 				= exports,
		IOCs 					= IOCs,
        injection_technique		= injection_technique,
        debug_flags_apis 		= debug_flags_apis,
        exception_based_apis	= exception_based_apis,
        timing_based_apis 		= timing_based_apis,
        interaction_based_apis	= interaction_based_apis,
        misc_apis				= misc_apis,
        packer					= packer,
        c2s_trackers			= c2s_trackers,
		obf						= obf,
		enc						= enc
	)


@app.route('/sample_upload', methods = ['GET', 'POST'])
def upload_file():
	# check if user logged in
	if "user_id" not in session:
		return redirect(url_for('login'))
	if request.method == 'POST':
        # Check if the post request has the file part
		if 'file' not in request.files:
			flash('No file part')
			return redirect(request.url)
		file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
		if file.filename == '':
			flash('No selected file')
            # return redirect(request.url)
		if os.path.exists('uploads/' + secure_filename(file.filename)):
			return redirect(url_for('analysis', filename = file.filename))
		if file:
			file.save('uploads/' + secure_filename(file.filename))
			return redirect(url_for('analysis', filename = file.filename))
	return render_template('upload.html')


@app.route('/unpack_samples', methods = ['GET'])
def unpack_samples():
	# uploaded sample full path
	path_to_exe = "packed-samples/{}".format(request.args.get("filename"))
	# unpacked sample full path
	unpacked_sample_name = "{}_unpacked.bin".format(request.args.get("filename").split(".")[0])
	# Init Unpacker
	unpacker = Unpacker(path_to_exe)
	# Init HashIdentifier
	hash_identifier = HashIdentifier(path_to_exe)
	# unpack sample
	is_unpacked = unpacker.detect_packers()
	# check if unpacked sample uses API Hashing
	is_hashed = hash_identifier.check_apis_hashing()
	# if sample is unpacked, calculate unpacked sample checksums
	md5_hash, sha1_hash, sha256_hash = None, None, None
	if is_unpacked:
		md5_hash, sha1_hash, sha256_hash = unpacker.calculate_unpacked_sample_checksums()
	return render_template("unpacker.html",
						unpacked_sample_name	= unpacked_sample_name,
						md5_hash				= md5_hash,
						sha1_hash				= sha1_hash,
						sha256_hash 			= sha256_hash,
						is_hashed				= is_hashed
	)


@app.route('/upload_packed_samples', methods = ['GET', 'POST'])
def upload_packed_samples():
	# check if user logged in
	if "user_id" not in session:
		return redirect(url_for('login'))
	
	if request.method == 'POST':
        # Check if the post request has the file part
		if 'file' not in request.files:
			flash('No file part')
			return redirect(request.url)
		file = request.files['file']
        # If the user does not select a file, the browser submits an empty file without a filename.
		if file.filename == '':
			flash('No selected file')
		if os.path.exists('packed-samples/' + secure_filename(file.filename)):
			return redirect(url_for('unpack_samples', filename = file.filename))
		if file:
			file.save('packed-samples/' + secure_filename(file.filename))
			return redirect(url_for('unpack_samples', filename = file.filename))
	return render_template('upload-packed-samples.html')


@app.route('/download_unpacked_sample', methods = ['POST'])
def download_unpacked_sample():
    # Construct the full file path
	file_path = "unpacked-samples/{}".format(request.form.get("sample_name"))
    # Check if the file exists
	if not os.path.exists(file_path):
		abort(404, description = "File not found")
    
	return send_file(file_path, as_attachment = True)


@app.route('/download_generated_mappings', methods = ['POST'])
def download_generated_mappings():
    # Construct the full file path
	file_path = "generated-hash-mappings/{}_mappings.txt".format(request.form.get("enum_name").split("_")[0])
    # Check if the file exists
	if not os.path.exists(file_path):
		abort(404, description = "File not found")
    
	return send_file(file_path, as_attachment = True)


@app.route('/manage_rules', methods = ['GET', 'POST'])
def manage_rules():
	# check if user logged in
	if "user_id" not in session:
		return redirect(url_for('login'))
	
	# get user rules
	user_id = session['user_id']
	rules = Rule.query.filter_by(owner_id = user_id).all()
	matched_rules = []
	# get matched rules
	for rule in rules:
		if rule.is_matched:
			matched_rules.append(rule)
	
	# check for POST request
	if request.method == "POST":
		rule_desc = request.form.get('rule_desc').strip()
		owner_id = session["user_id"]
		date_added = datetime.now().strftime("%d-%m-%Y")
		is_matched = False
		# add rule
		new_rule = Rule(rule_desc = rule_desc, owner_id = owner_id, date_added = date_added, is_matched = is_matched)
		try:
			db.session.add(new_rule)
			db.session.commit()
			return redirect(url_for('manage_rules'))
		except:
			db.session.rollback()
			
	return render_template('manage-rules.html', rules = rules, matched_rules = matched_rules)
		

@app.route('/delete_rule/<int:rule_id>', methods = ['POST'])
def delete_rules(rule_id):
	rule = Rule.query.filter_by(id = rule_id).first()
	try:
		db.session.delete(rule)
		db.session.commit()
		return jsonify({"message": "Rule deleted successfully"}), 200
	except Exception as e:
		db.session.rollback()
		return jsonify({"error": str(e)}), 500
	

@app.route('/match_rules', methods = ['POST'])
def match_rules():
	# parse json data
	params = request.json
	iocs = params.get("iocs")
	exe_path = params.get("exe_path")
	# get all rules
	rules = Rule.query.all()
	# check if any rules match
	for rule in rules:
		if rule.rule_desc in iocs:
			rule.is_matched = True
			rule.sample_url = exe_path
			rule.date_matched = datetime.now().strftime("%d-%m-%Y")
	# commit updates
	try:
		db.session.commit()
		return jsonify({"message": "success"}), 200
	except Exception as e:
		db.session.rollback()
		return jsonify({"error": str(e)}), 500


@app.route('/download_matched_sample', methods = ['POST'])
def download_matched_sample():
	# sample full path
	sample_path = request.form.get("sample_path")
	# Check if the file exists
	if not os.path.exists(sample_path):
		abort(404, description = "File not found")
    # send file as an attachment
	return send_file(sample_path, as_attachment = True)


@app.route('/signup', methods = ['GET', 'POST'])
def signup():
	# check if user logged in
	if "user_id" in session:
		return redirect(url_for('upload_file'))
	
	if request.method == "POST":
		name = request.form.get('name')
		email = request.form.get('email')
		password = request.form.get('password')
		# Hash the password with SHA-1
		password_hash = hashlib.sha1(password.encode()).hexdigest()

		new_user = User(name = name, email = email, password = password_hash)
		
		try:
			db.session.add(new_user)
			db.session.commit()
			return redirect(url_for('login'))
		except:
			db.session.rollback()
			return render_template('signup.html', user_exists = True)
	return render_template('signup.html')


@app.route('/login', methods = ['GET', 'POST'])
def login():
	# check if user logged in
	if "user_id" in session:
		return redirect(url_for('upload_file'))
	if request.method == 'POST':
		email = request.form.get('email')
		password = request.form.get('password')

		user = User.query.filter_by(email = email).first()
		if user and user.password == hashlib.sha1(password.encode()).hexdigest():
			session['user_id'] = user.id
			return redirect(url_for('upload_file'))
		else:
			return render_template('login.html', invalid_credentials = True)
    
	return render_template('login.html')


@app.route("/logout", methods = ["GET"])
def logout():
	# delete user cookie and redirect to login page
	res = make_response(redirect("/login", code = 302))
	res.delete_cookie("session")
	return res


@app.route("/api/v3/users", methods = ["POST"])
def get_user_files():
	try:
		user_uuid = request.get_json()["user_uuid"]
		if user_uuid != None:
			if user_uuid == "5d59daf3-f7cb-4a79-8c69-ec657aebb89a":
				user_files = os.listdir("users/5d59daf3-f7cb-4a79-8c69-ec657aebb89a/")
				return jsonify(user_files)
			return "invalid uuid", 401
		else:
			return "invalid uuid", 401
	except:
		return "invalid uuid", 401


@app.route("/api/v3/upload", methods = ["POST"])
def upload_files_via_url_v3():
	# check if user is logged in
	uuid_hash = request.cookies.get("uuid_hash")
	if uuid_hash == None:
		return redirect("/login", code = 302)
	# block all requests to localhost
	file_url = request.form.get("file_url")
	try:
		file_domain = file_url.split("/")[2].split(":")[0]
		request_ip = socket.gethostbyname(file_domain)
		if request_ip.startswith("127") or \
		request_ip.startswith("0") or \
		request_ip.startswith("192"):
			return "invalid url\n", 403
		file_name = file_url.split("/")[-1]
		file_contents = requests.get(file_url).text
		fd = open(f"users/5d59daf3-f7cb-4a79-8c69-ec657aebb89a/{file_name}", "w")
		fd.write(file_contents)
		fd.close()
		return file_contents
	except:
		return "invalid url\n", 403


@app.route("/api/v2/upload", methods = ["POST"])
def upload_files_via_url_v2():
	uuid_hash = request.cookies.get("uuid_hash")
	if uuid_hash == None:
		return redirect("/login", code = 302)
	content_type = request.headers.get("Content-Type")
	# block all requests to localhost
	if content_type == "application/x-www-form-urlencoded":
		try:
			file_url = request.form.get("file_url")
			file_domain = file_url.split("/")[2].split(":")[0]
			request_ip = socket.gethostbyname(file_domain)
			if request_ip.startswith("127") or \
			request_ip.startswith("0") or \
			request_ip.startswith("192"):
				return "invalid url\n", 403
			file_name = file_url.split("/")[-1]
			file_contents = requests.get(file_url).text
			fd = open(f"users/5d59daf3-f7cb-4a79-8c69-ec657aebb89a/{file_name}", "w")
			fd.write(file_contents)
			fd.close()
			return file_contents
		except:
			return "invalid url\n", 403
	else:
		try:
			file_url = urllib.parse.unquote(request.get_json()["file_url"])
			file_domain = file_url.split("/")[2].split(":")[0]
			request_ip = socket.gethostbyname(file_domain)
			if request_ip.startswith("127") or \
			request_ip.startswith("0") or \
			request_ip.startswith("192"):
				return "requests to localhost not allowed\n", 403
			time.sleep(1)
			headers = {"X-Request-Ip": "127.0.0.1"}
			res = requests.get(file_url, headers = headers)
			file_contents = res.text
			status_code = res.status_code
			return file_contents, status_code
		except:
			return "requests to localhost not allowed\n", 403


@app.route("/api", methods = ["GET", "POST"])
def api_docs():
	# only accessible from localhost
	request_src_ip = request.headers.get("X-Request-Ip")
	if request_src_ip == None or request_src_ip != "127.0.0.1":
		return "Not Found", 404

	return """/users
	/status
	/employees
	""", 200


@app.route("/api/users", methods = ["GET", "POST"])
def get_users_uuids():
	# only accessible from localhost
	request_src_ip = request.headers.get("X-Request-Ip")
	if request_src_ip == None or request_src_ip != "127.0.0.1":
		return "Not Found", 404

	# get user files
	user_uuid = request.args.get("uuid")
	if user_uuid != None:
		user_files = os.listdir(f"users/{user_uuid}/")
		return jsonify(user_files)
	else:
		# get all users uuids
		users = os.listdir("users/")
		return jsonify(users)
	

@app.route('/contact_us', methods = ['GET', 'POST'])
def contact_us():
	is_sent = False
	if request.method == "POST":
		is_sent = False
		name = request.form.get("name")
		email = request.form.get("email")
		message = request.form.get("message")
		with open("contacts/contacts.txt", "a") as h:
			h.write("{}_{}_{}\n".format(name, email, message))
			is_sent = True
		return redirect(url_for('main', is_sent = is_sent))
	return redirect(url_for('main', is_sent = is_sent))


@app.route("/api/status", methods = ["GET", "POST"])
def get_site_status():
	# only accessible from localhost
	request_src_ip = request.headers.get("X-Request-Ip")
	if request_src_ip == None or request_src_ip != "127.0.0.1":
		return "Not Found", 404
	return "site is up", 200


@app.route("/api/employees", methods = ["GET", "POST"])
def get_employees():
	# only accessible from localhost
	request_src_ip = request.headers.get("X-Request-Ip")
	if request_src_ip == None or request_src_ip != "127.0.0.1":
		return "Not Found", 404
	return "we currently have 1337 active employees"


@app.errorhandler(404)
def page_not_found(e):
	return "resource not found", 404


if __name__ == '__main__':
	with app.app_context():
		db.create_all()
	app.run(debug = False, host = "0.0.0.0", port = 80)

