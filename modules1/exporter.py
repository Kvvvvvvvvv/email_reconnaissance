import csv

def export_to_csv(data, filename="output.csv"):
    keys = data.keys()
    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerow(data)