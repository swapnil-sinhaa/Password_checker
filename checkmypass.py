import requests
import hashlib #built-in module for SHA1 hashing the password
import sys

# url = 'https://api.pwnedpasswords.com/range/'+'2CF24'
# res = requests.get(url)
# print(res)

#Requesting the api through a function
def request_api_data(query_char):
	url = 'https://api.pwnedpasswords.com/range/'+ query_char
	res = requests.get(url)
	if res.status_code != 200:
		raise RuntimeError(f'Error fetching: {res.status_code},check the api and try again')
	return res

#To get a list of responses that match our first 5 letters of Hash
def get_password_leaks_count(hashes,hash2check):
	#the hash is splited by ':'and saved in hashes and done by "splitlines"
	hashes = (line.split(":") for line in hashes.text.splitlines())
	# # To get both the items seperately, we loop through it
	for h, count in hashes:
		if h == hash2check:
			return count 
	return 0
		# print(h, count)
	# print(f'{hashes},{hash2check}')

#Taking our password and creating the hash and checking it
def pwned_api_check(password):
	# code to get the hashing (standard)
	sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper() 
	#taking the first 5 and last 5 charac. from hash
	first5char, tail = sha1password[:5], sha1password[5:]
	#putting the response in the main query
	response = request_api_data(first5char) 
	#Password checker is working as for first 5 characters it is finding the rest of the tail in a hash, 
	# therefore all the last digits i.e. tail
	# is for the first 5 characters and we have to input tail in the function to check if it is for the same.
	return get_password_leaks_count(response,tail)


def main(args):
	for password in args:
		count = pwned_api_check(password)
		if count:
			print(f'Your password {password} has been hacked {count} times.')
		else:
			print(f'Password {password} not found!')
		return 'done!'

if __name__ == '__main__': #program will run only when the main file will run i.e. this one.
	f = open(sys.argv[1], 'r')
	contents = f.read()
	sys.exit(main(contents)) # reading input from CMD window as "python checkmypass.py hello" so reading hello