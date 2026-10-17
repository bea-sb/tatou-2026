# tatou
A web platform for pdf watermarking. This project is intended for pedagogical use, and contain security vulnerabilities. Do not deploy on an open network.

## Instructions

The following instructions are meant for a bash terminal on a Linux machine. If you are using something else, you will need to adapt them.

To clone the repo, you can simply run:

```bash
git clone https://github.com/nharrand/tatou-2026.git
```

Note that you should probably fork the repo and clone your own repo.


### Run python unit tests

```bash
cd tatou/server

# Create a python virtual environement
python3 -m venv .venv

# Activate your virtual environement
. .venv/bin/activate

# Install the necessary dependencies
python -m pip install -e ".[dev]"

# Run the unit tests
python -m pytest
```

### Deploy

From the root of the directory:

```bash
# Create a file to set environement variables like passwords.
cp sample.env .env

# Edit .env and pick the passwords you want

# Rebuild the docker image and deploy the containers
docker compose up --build -d

# Monitor logs in realtime 
docker compose logs -f

# Test if the API is up
http -v :5000/healthz

# Open your browser at 127.0.0.1:5000 to check if the website is up.

```

### How to upload file

Either drag and drop a file or pick one through the directory button(Choose file), pick a name that has at least one letter and upload. You might get an error message, yet wait one second and then refresh and then it will be there.

### How to use xmp watermark 

Needs a secret value and key for the secret value that is embedded in the meta data to be encrypted with the key. This is simply to avoid the embedded secret being in clear text if the meta data can be viewed in for example pdf view applications and therefore protects its confidentiality. The watermark method also provides the option for an intended for which is written out visually on the page and an optional position for the visual watermark text which is in five predetermined locations, bottom left, center, bottom right, top left and top right. If position is not chosen it defaults to bottom right. 

### Good Watermarker Generator 

Needs a secret key value if you want a secret message in the pdf file. It also provides a visible watermark through image stamps and a text for what intended user you put in. The watermark does not account for a position so there is no need to input one. It does require a key, and a secret to work.

### How to read the watermark 
Download the watermarked version of the document. Then upload the watermarked document to the website and use the read watermark button. Then pick the used watermark method, type in the key and optionally type in position. If any of these values are wrong for the specific document you will get an error message otherwise you will see the secret value that was embedded in the watermark.

### RMAP

You need a private and public key within a keys folder and the clients which you have decided can visit. The keys folder will be available in the collection of chosen artifacts folder. To execute you need to cd server/rmap and execute the file rmat.py by if you are on windows “python rmat.py” You need to be there as the path to the keys folder is hardcoded. And the keys folder needs to be placed within the server dir for building the docker to work as expected.

If the problem occurs that the PASSPHRASE is not set and or empty. Just set it locally with: $env:PASSPHRASE=”Your_secret_little_passphrase” 

### test running 

Pytest. We used the command “docker compose exec server pytest -q” to run the tests

### coverage analysis 

For coverage analysis we used this command in the terminal “docker compose exec server pytest --cov=server --cov-report=term-missing --cov-report=html -q” after pip installing pytest -cov


### Fuzzing 

To use the fuzzing tool Schemathesis you have to download it into your local venv. You can do so with “pip install schemathesis”. You have to be in the same dir as the testapi.yaml and server.py for it to work properly. A login bearer token is needed for the tests which require authentication. To get a token you must have an account through Tatou or make one specifically for testing. As documents can otherwise be deleted on that user which bears the token.

For windows:
$body = @{ email = "fuzz@test.com"; password = "test" } | ConvertTo-Json

Check that the $body is not empty by simply running: “$body”

$response = Invoke-RestMethod -Uri "http://localhost:5000/api/login" -Method Post -ContentType "application/json" -Body $body

Check that the $response is not empty by simply running: “$response”

$token = $response.token

Then you can check that the token isn't empty by “$token”
And when you have a token for a test user you can then run:
schemathesis run testapi.yaml --url http://localhost:5000/ -H "Authorization: Bearer $token"

### To access the logs 

Run the docker compose logs -f in the terminal. Can also be filtered in the terminal for a specific time period due to the observation points now having timestamps in UTC time zone. 

