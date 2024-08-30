https://www.reddit.com/r/OSINT/comments/192wpkc/osint_challenge_multiple_difficulties/

## Question 1

Question: What are the coordinates of this picture?

### Solution

In the picture we can clearly see a sign that says arts and design district, a quick google search led me to their [website](https://carmelartsanddesign.com/contact/). The website lists the address which is in Indiana.

After a lot of searching looks like I found the location of the security camera [here](https://www.google.com/maps/place/Carmel+Arts+%26+Design+District,+%D7%9B%D7%A8%D7%9E%D7%9C,+%D7%90%D7%99%D7%A0%D7%93%D7%99%D7%90%D7%A0%D7%94+46032,+%D7%90%D7%A8%D7%A6%D7%95%D7%AA+%D7%94%D7%91%D7%A8%D7%99%D7%AA%E2%80%AD/@39.9781062,-86.1271109,3a,75y,83.46h,92.8t/data=!3m10!1e1!3m8!1sSa1nf9V9_iQRXYv2sT_clw!2e0!6shttps:%2F%2Fstreetviewpixels-pa.googleapis.com%2Fv1%2Fthumbnail%3Fcb_client%3Dmaps_sv.tactile%26w%3D900%26h%3D600%26pitch%3D-2.7972619013572455%26panoid%3DSa1nf9V9_iQRXYv2sT_clw%26yaw%3D83.46185689518413!7i16384!8i8192!9m2!1b1!2i38!4m7!3m6!1s0x8814adc9c185e2c9:0x1c467db2e8eebbae!8m2!3d39.9757238!4d-86.1268337!10e5!16s%2Fg%2F1tfn3bjr?coh=205410&entry=ttu&g_ep=EgoyMDI0MDgyMS4wIKXMDSoASAFQAw%3D%3D).

Coordinates: 39.9781062,-86.1271109

## Question 2

Question: Can you find the link to the CCTV camera? What's the name that's being covered?

### Solution

Searching Google for indiana carmel security camera, I was able to find the [link](https://www.earthcam.com/usa/indiana/carmel/?cam=carmel) at the end of the second page to the security camera. The hidden name is EarthCam.

## Question 3

Question: What's the exact date and hour when this picture was taken?

### Solution

Searching the security camera, the time when the red tape in the photo is installed is in 11/16/2022, the earliest date for the photo.

Upon a second look some of the tape in the original photo from the security cameras year 2022 is missing, now we have a new earliest data of 11/21/2023.

The tape is removed on 01/16/2024, so the possible date range is:

11/21/2023 - 01/16/2024.

Looking through the photos of the camera in this date range, we can find the original photo. The date is 12/24/2023.

Looking what is the average height of a bus in Google, we can see it's 3.81.

By drawing a line of the shadow (roughly), then looking at the properties, we can conclude it's about 8.25 meters.

Using [this](https://www.carbidedepot.com/formulas-trigright.asp) trigonometry calculator, I was able to find the degree of A which is 24.78.

Entering the date, coordinates, and bus height to SunCalc, by the direction of the sun we can pin point the time to around 13:51.

tip: If there is no good visibility of the shadow in the image, we can bring up the contrast and bring down the exposure.