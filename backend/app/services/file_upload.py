import os
from uuid import uuid4
from fastapi import UploadFile
from PIL import Image

UPLOAD_FOLDER = "static/profile_pics"

async def save_profile_picture(file: UploadFile) -> str:
    filename = f"{uuid4().hex}.jpg"
    file_path = os.path.join(UPLOAD_FOLDER, filename)

    with open(file_path, "wb") as buffer:
        buffer.write(await file.read())

    # Resize the image
    img = Image.open(file_path)
    img.thumbnail((125, 125))
    img.save(file_path)

    return filename
