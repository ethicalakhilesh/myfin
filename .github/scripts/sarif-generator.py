import json
import hashlib

def coordinates(filepath, target, returnType):
    with open(filepath, 'r', encoding='utf-8') as f:
        text = f.read()
    i = text.find(target)
    if i == -1: return None

    lineStart = text[:i].count('\n') + 1
    columnStart = i - text.rfind('\n', 0, i) if '\n' in text[:i] else i + 1
    lineStart = lineStart + target.count('\n')
    columnEnd = len(target.split('\n')[-1]) if '\n' in target else columnStart + len(target) - 1

    return {
        0: lineStart,
        1: columnStart,
        2: lineStart,
        3: columnEnd
    }.get(returnType, [lineStart, columnStart, lineStart, columnEnd])

def findingType(types):
    return f"Secret detected: {types}\nMatches: [{types}](0)"

def issues(finding):
    issue = {}
    issue["ruleId"] = str(finding.get("types", [])[0])
    issue["level"] = "error"
    issue["message"] = {
        "text": findingType(finding.get("types", [])[0]),
        "markdown": findingType(finding.get("types", [])[0])
    }
    issue["locations"] = [
        {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": finding.get("filename")
                },
                "region": {
                    "startLine": coordinates(finding.get("filename"), finding.get("secrets"), 0),
                    "startColumn": coordinates(finding.get("filename"), finding.get("secrets"), 1),
                    "endLine": coordinates(finding.get("filename"), finding.get("secrets"), 2),
                    "endColumn": coordinates(finding.get("filename"), finding.get("secrets"), 3)
                }
            }
        }
    ]
    # issue["partialFingerprints"] = {
    #     "secret/v1": hashlib.sha256(finding.get("secrets").encode("UTF-8")).hexdigest()
    # }
    return issue

def formatting(input_path):
    with open(input_path, 'r') as infile:
        data = json.load(infile)

    sarif = {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "organization": "Yelp",
                        "name": "Detect Secret (Yelp)",
                        "version": "1.5.0",
                        "informationUri": "https://github.com/Yelp/detect-secrets",
                    }
                },
                "results": []
            }
        ]
    }

    results = sarif["runs"][0]["results"]
    for finding in data.get("results", []):
       results.append(issues(finding))

    return sarif

# Example usage
if __name__ == "__main__":
    data = formatting("report.json")

    with open("results.sarif", 'w') as outfile:
        json.dump(data , outfile, indent=4)

    print(f"SARIF file generated successfully: results.sarif")
