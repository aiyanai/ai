# process.py

from questions import q
import subprocess
import json

# Endpoint URL for bitnet
bitnet_url = "http://172.18.43.168:8080"
output_file = "llama32.res"

def get_bitnet_answer(question):
    command = [
        "curl", "-X", "POST", bitnet_url,
        "-H", "Content-Type: application/json",
        "-d", json.dumps({"query": question})
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error retrieving answer for question '{question}': {e}")
        return "Error"

def save_answers_to_file():
    q_dict = q()
    with open(output_file, "w") as f:
        for category, questions in q_dict.items():
            f.write(f"Category: {category}\n")
            for question in questions:
                answer = get_bitnet_answer(question)
                f.write(f"Question: {question}\nAnswer: {answer}\n\n")
                print(f"Saved answer for question: '{question}'")

# Run the function
save_answers_to_file()
