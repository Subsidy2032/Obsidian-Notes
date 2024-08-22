#Forensics

The application of computer science to investigate digital evidence for legal purposes

**Public-sector investigations:** Carried out by the government and low enforcement agencies, would be part of crime or civil investigation

**Private-sector investigations:** Carried out by corporate bodies by assigning a private investigator, triggered by corporate policy violations

## Steps:

1. Acquire the evidence
2. Establish a chain of custody
3. Place the evidence in a secure container
4. Transport the evidence to your digital forensics lab
5. Retrieve the digital evidence from the secure container
6. Create a forensic copy of the evidence
7. Return the digital evidence to the secure container
8. Start processing the copy on your forensics workstation

**Metadata:** Gives information about the file such as creation date and last modification date

`pdfinfo` - Tool for viewing metadata of a pdf document such as title, subject, author, creator and creation date

**Exchangeable Image File Format (EXIF):** Standard for saving metadata into image files
like:

- Camera model/Smartphone model
- Date and time of image capture
- Photo settings such as focal length, aperture, shutter speed, and ISO settings

And maybe even GPS coordinates of where the photo was taken

`exiftool` - Used to read and write metadata in various file types such as JPEG images