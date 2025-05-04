import json
import hashlib

# Load input and output templates
with open('report.json') as f:
    input_data = json.load(f)

with open('./.github/scripts/output-format.json') as f:
    output_template = json.load(f)

# Initialize results list
converted_results = []

# Loop over each entry in input data
for item in input_data['results']:
    filename = item['filename']
    for secret_type in item['types']:
        secret_content = item['secrets']
        line_number = int(list(item['lines'].keys())[0])
        line_content = list(item['lines'].values())[0]
        start_column = line_content.find(secret_content) + 1  # +1 to convert to 1-based indexing
        end_column = start_column + len(secret_content) - 1

        # Compute partial fingerprint
        # md5_hash = hashlib.md5(secret_content.encode()).hexdigest()
        # sha256_hash = hashlib.sha256(md5_hash.encode()).hexdigest()

        result = {
            "ruleId": secret_type,
            "level": "error",
            "message": {
                "text": secret_type,
                "markdown": secret_type
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": filename
                        },
                        "region": {
                            "startLine": line_number,
                            "startColumn": start_column,
                            "endLine": line_number,
                            "endColumn": end_column
                        }
                    }
                }
            ] #,
            # "partialFingerprints": {
            #     "secret/v1": sha256_hash
            # }
        }

        converted_results.append(result)

# Assign converted results to the output template
output_template['runs'][0]['results'] = converted_results

# Save the output
with open('results.sarif', 'w') as f:
    json.dump(output_template, f, indent=4)

print("Mapping complete. Output written to 'mapped-output.json'")
