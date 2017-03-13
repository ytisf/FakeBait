# Fakebait
## Abstract

**FakeBait** was born out of the process of AV replacement. As we approached a growing need of replacing our current AV vendor we have started considering various aspects of the new AV we might need. As there were no "tools" in order to evaluate the efficiency of an AV package, from detection and up to communication mitigation we have created this little script.

## Method
As *modous di operandi* we have choosed to test several detection and mitigation responsilibilties in various ways.
### Malware File Detection
  1. This package arrives we several malwares prepacked in ZIP format. The archives are encrypted with the very complex and secure password of `infected` which no AV could ever guess.
  2. **fakebait** will then decompress these malwares one by one and wait for a short period of time and then test to see if the file extracted still located. In a case the file has been removed **fakebait** will assume the removal we done due to detection by the AV.

### EICAR Test
  4. The EICAT test is using the EICAR file to drop it in various ways to see if they are being picked up at any point.
  5. The tests which are done are:
    6. Get the EICAR file from the EICAR URL.
    7. Write it to a file as Base64.
    8. Write to a file as Plain Text.
    9. Append it to a small PNG.
    10. Gzip it and save to a file.
    11. Create a ZIP file with size of `3.1415 GB` and put it there as well.

### Malware Communication Detection
This one is kind of straight forward, got a list of malware sites (serving or C&C) - try and do the following stages and see where and when the script is failing:

DNS Resolution --> Connect to Port 80/tcp --> Do a `GET` Request

## Report
