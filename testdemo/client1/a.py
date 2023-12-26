import mimetypes

file_path = "./data/a.py"

media_type, encoding = mimetypes.guess_type(file_path)

print(f"Media Type: {media_type}")
print(f"Encoding: {encoding}")