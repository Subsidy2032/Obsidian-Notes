## Question 0 - Twitter

Question: On March 28, 2018 I ([Sector035](https://twitter.com/sector035)), quoted a tweet by someone else that could very well be a nice geolocation challenge. But what is the **display name** of the Twitter account that sent out this quiz?

### Solution

Using the search query `until:2018-03-29 since:2018-03-28 Sector035` we can find the retweet.

Answer: Rickey Gevers

## Question 1 - Twitter

Question: Julia Bayer started the [Quiztime](https://twitter.com/quiztime) movement back in April 2017. She started using the hashtag **#MondayQuiz** for her, back then, weekly challenges. But can you tell me what the last text was that she tweeted in 2017, while using the hashtag **#MondayQuiz**? Make sure to only take the text that she typed. So no Unicode characters, emoticons, hashtags or anything else.

### Solution

Using the search query `#MondayQuiz Julia Bayer until:2018-01-01 since:2017-04-01` and then going to latest, we can see the last tweet from Julia Bayer with the hashtag #MondayQuiz in 2017.

Answer: Merry Christmas

## Question 2 - Instagram

Question: Quiztime crew member [Tilman Wagner](https://twitter.com/twone2) posted an image on Instagram on May 12, 2020 that featured a car. In the URL itself you see the unique identifier of the post (called a 'shortcode' by Instagram), which consists of a bunch of numbers and letters in both lowercase and uppercase. But somewhere there is also a numerical 'ID', which can be found in the source of the page, or in some 'JSON output'. But what is this number?  
  
If you're not familiar with JSON yet, I'd suggest you read [this article](https://osintcurio.us/2019/08/15/json-and-common-web-encodings-demystified/) , that talks about a few different types of data and encoding that you might encounter while investigating websites.  
  
_Note 1: The original quiz question featured a post from 2018. The MD5 hash of that answer will also be accepted._  
_Note 2: Since June 2022, Instagram has changed the way it works, and the hint for this question has changed._

### Solution

After finding the [profile](https://instagram.com/twoneplus) and there the image that features a car, we can click on the image, go to the page source, and search for 'media_id' in order to find the post ID.

Answer: 2307256208945377525

## Question 3 - Google Search

Question: In September 2019 someone posted in an aviation forum a quote that explained how [Christiaan Triebert](https://twitter.com/trbrtc) was using shadows, that were cast by towers around a launch pad, as sun dials. But what is the username of the account that posted this?

### Solution

Searching `intext:@trbrtc intext:shadows after:2019-09-01 before:2019-10-01` in google we can see the first [result](https://www.airliners.net/forum/viewtopic.php?t=1430561) is the post talked about.

Answer: Tugger

## Question 4 - Images

Question: There is a weird artwork in Indianapolis that has its own [Wikipedia entry here](https://en.wikipedia.org/wiki/Funky_Bones) .  
  
The photo featured on the Wikipedia page can be found all over the internet, but one of the oldest uploads out there is on a certain stock photo site. Are you able to find this stock photo site? The answer is the **original** filename, including its file extension.

### Solution

Reverse google searching and going to getty images, we can see the original image name in the details section.

Answer: 2010_in-an-at0552v02.jpg

## Question 5 - Videos

Question: For this question I'm going to feature the awesome [Nico 'Dutch OSINT Guy' Dekens](https://twitter.com/dutch_osintguy). We'll be looking at a YouTube video, and you will need to find some online tool to view additional information about the video. Can you tell me what the date and time of publishing is of the following video?  
  
Link to the video: [https://www.youtube.com/watch?v=kUVFeXSdkO8](https://www.youtube.com/watch?v=kUVFeXSdkO8)   
  
Extract the date and time you found, and send it in it as follows:  
  
`yyyymmddhhmmss`

### Solution

Going to [Mattw.io](https://www.youtube.com/watch?v=kUVFeXSdkO8) we can find the publish time in the metadata. We can also go to [Amnesty](https://citizenevidence.amnestyusa.org/), the [Amnesty](https://citizenevidence.amnestyusa.org/), [InVID/WeVerify plugin](https://weverify.eu/verification-plugin/), and so on.

Answer: 20200604191958

### Question 6 - Images

Question Time to have a crack at the following image:  
  

![](https://sector035.nl/quiz/beginners/content/6.jpg)

  
  
Provide the full name, so first and last name, of the person who initially uploaded it to a 'wiki' platform.

### Solution

After a lot of searching and then doing a reverse search again on a more complete image I found, I stumbled upon [this](<https://commons.wikimedia.org/wiki/File:Graffiti_art,_Epplehaus_T%C3%BCbingen_(2018).jpg>) that mentions the author.

Answer: Olga Ernst

## Question 7 - Source Code

Question: in February 2019 Reddit user 'Webbreacher' shared the playlist of the 10-minute tips over on Reddit. Find this message, and extract the Unix 'timestamp' of this post. Whether you're logged in at Reddit or not, you can find it somewhere in the source of the page. Not sure what the Unix 'timestamp' is? Then check out the hint!

### Solution

Going to reddit and searching for "u/Webbreacher 10-minute tips" brought us to [this](https://www.reddit.com/r/OSINT/comments/astzbt/osintcurious_10_minute_tips/) page. Searching for timestamp in the page source we find this line:
`;created_timestamp&quot;:1550697885464`
Which contains the Unix timestamp.

Answer: 1550697885464

## Question 8 - JSON

Question: For this question, we'll be looking at a scan of the website [https://osintcurio.us](https://osintcurio.us)  that was performed by urlscan.io in early 2019. Open the following link, and click around to have a look at all the information that was saved. This question can only be answered by looking for a screen with lots of JSON output, and have a good look at how much more information is in there, compared to the web interface:  
  
[https://urlscan.io/result/2d8a4cdb-6c43-4925-a9f9-d99750cf3f8b/](https://urlscan.io/result/2d8a4cdb-6c43-4925-a9f9-d99750cf3f8b/)   
  
When this scan was made, the web server sent out slightly different so-called 'HTTP response headers' than it does nowadays. Please provide the exact text that was sent in the '**X-Hacker**' header.

### Solution

By clicking the API key we get a JSON page with a wealth of information.

We can find the text that is sent in the X-Hacker header under: requests -> 0 -> response -> response -> headers -> X-hacker.

Answer: If you're reading this, you should visit automattic.com/jobs and apply to join the fun, mention this header.

## Question 9 - Developer Tools

Question: For this question, we'll look at some more JSON output, just to give you some extra practice. You'll only need your browser and its developer tools again. Open the following site, and answer the question:  
  
[http://www.virtualradar.nl/virtualradar/desktop.html](http://www.virtualradar.nl/virtualradar/desktop.html)   
  
By looking at the traffic between your browser and the website, and looking at the JSON, can you deduct the name of the variable that shows the total amount of aeroplanes currently tracked within the view you've selected?

### Solution

Answer: totalAc

## Question 10 - EXIF & Metadata

Question: For a Quiztime geolocation challenge [Fiete Stegers](https://twitter.com/fiete_stegers) tweeted a photo from his new workplace a few years ago. Nowadays, a lot of social media remove most metadata of images or videos. But when you download media files from a website, it sometimes pays off to check whether the metadata, or EXIF information, of a file is still there. With the photo I give you here, it should be possible to find out what the location of the building is.  
  
To answer the question: Don't bother geolocating the building itself, that would be too easy! I want you to find the GPS coordinates in the file itself. Make sure to retrieve it, or convert it to the following decimal format:  
  
`yy.yyyy,xx.xxxx` _(that is: latitude, longitude)_  
  
_Note: Make sure to cut off the coordinates at 4 numbers after the decimal!_

![[10.jpg]]

### Solution

Going to [this](https://www.metadata2go.com) site we can upload the image and see the degrees of the longitude and latitude.

After that in [this](https://www.gps-coordinates.net/) site we can convert it to the requested format.

Answer: 53.5566,10.0220

## Question 11 - EXIF & Metadata

Question: One of the Quiztime crew members is [Philipp Dudek](https://twitter.com/dondude), and he was part for HHLab, until they stopped in August 2022. On their website they had a list of people that worked there, and this is the profile photo that was used for Philipp:  
  

![](https://sector035.nl/quiz/beginners/content/11.png)

  
  
It's time to take a closer look at his profile photo, that used to be on the original website. Can you find out the first name of the person who most likely edited this photo?

### Solution

Tools that can help see metadata: [Forensically](https://29a.ch/photo-forensics/#forensic-magnifier), [Exiftool](https://exiftool.org/), and [Bless](https://qiita.com/itsmarttricks/items/a7c1e3bb2d42f92a3e3f). Other hex editors other then Bless, like [HxD](https://mh-nexus.de/en/hxd/) can be used as well.

Going to [this](https://www.metadata2go.com/view-metadata) site again, we can see C:\Users\Marc\Desktop\Philopp.png in the history section of the metadata. It looks like the picture is created from Marc's computer.

Answer: Marc

## Question 12 - EXIF & Metadata

Question: Time to dive one last time into EXIF data with a fairly easy question. Open the following website and extract the EXIF information from the image of the typewriter. You might not be able to download this image right away, so maybe use the developer tools to find the direct URL to download it. Go have a look at the abundance of information inside the EXIF data:  
  
[https://www.behance.net/gallery/11820853/Type-Investigation](https://www.behance.net/gallery/11820853/Type-Investigation)   
  
The answer for this question is the value of the "Legacy IPTC Digest".

### Solution

Just like with the other EXIF challenges I went to [this](https://www.metadata2go.com/view-metadata) site again, searched for IPTC and found the answer.
\
answer: F5B9EFCFD52592DC2821842599A3416F

## Question 13 - History & Archives

Question: The website of the [OSINT Curious Project](https://osintcurio.us)  was launched end of 2018. Back in the early days the '**robots.txt**', that you can find in the root (or top folder) of most web servers, featured a date. That file still exists today, but no longer contains the date. Time for you to dive into history and find this exact date!  
  
Grab the date and time mentioned in that file, and submit it, using the following format: **yyyymmddhhmmss**

### Solution

Simply going to the Wayback Machine website, going to the oldest archive available for the website, and looking for the robots.txt file revealed the date.

Answer: 20181205204127

## Question 14 - History & Archives

Question: [Marco Bereth](https://twitter.com/mahrko) is one of the people that sends out quizzes for Quiztime. Back in 2013 his Twitter bio was quite different compared to his current one. But what was the very **first** word in his profile back in July 2013?

### Solution

Going to the wayback machine, then searching for https://twitter.com/mahrko and then the date that is closest to July we can find his old bio. [archive.today](https://archive.md/) is one more archive website that can be used.

Answer: Bahnfahrer

## Question 15 - History & Archives

Question: Using the website [Elephind](https://elephind.com/), you'll be searching for articles about open source intelligence.  
  
Find a newspaper from October 29, 2007. The term is mentioned in a calendar of some kind. Find the calendar item in question, and look for the name of the person that is mentioned. What is his name?

### Solution

Since the newspaper archive mentioned doesn't exist anymore, I accessed [it](http://web.archive.org/web/20220804035137/https://elephind.com/) through the Wayback machine website. The way back machine didn't archive this page, and looking at more archives and using google dorking also returned nothing. It is possible that this article is still somewhere in the wild, but I have decided to move on.

Answer: Frank Pabian

## Question 16 - Geolocation & Chronolocation

Question: This statue can be found somewhere in the world and even has its own 'square'. Can you find out where this statue is and find the name of the 'square'?  
  

![](https://sector035.nl/quiz/beginners/content/16.jpg)

  
The answer is the name of this 'square', in the original language.

### Solution

This time looking at the metadata in [this site](https://www.metadata2go.com) gives us nothing.

First reverse searching the ambulance in the photo brought me [here](https://www.facebook.com/duesseldorf.feuerwehr/posts/einsatz%C3%BCbung-manv-gestern-fand-die-j%C3%A4hrliche-manv-%C3%BCbung-in-d%C3%BCsseldorf-statt-geme/2706623822699670/?locale=de_DE), the exact same ambulance and the language seems to be German.

After a lot of searches couldn't find anything similar or a way to narrow the location. I saw a writeup and the image that brought him to the solution does not exist anymore, even after searching for the location I couldn't find an image with similar surroundings.

Answer: Johannes-Rau-Platz

## Question 17 - Geolocation and Chronolocation

Question: For this question have a look at a beautiful photo posted on Instagram by [Tilman Wagner](https://twitter.com/twone2). To go to the last question, submit the postal code of the square where the statue is located.  
  
Link: [https://www.instagram.com/p/Bqj00zHAsgK](https://www.instagram.com/p/Bqj00zHAsgK/)

### Solution

Doing a reverse image search I found [this](https://www.flickr.com/photos/kolibri000/) image.

I also found [this](https://upload.wikimedia.org/wikipedia/commons/f/f6/Norway_2016-03-13_%2826434496772%29.jpg) image which brought me [here](<https://commons.wikimedia.org/wiki/File:Norway_2016-03-13_(26434496772).jpg>), we now now that the image is taken in Norway, Oslo, Devant la Gare Centrale. Searching this location in Google maps brought me to Oslo's central station, I was then able to find the postal code of Oslo's central station with a simple google search.

Answer: 0154

## Question 18 - Geolocation and Chronolocation

Question: Look at the following image by Julia Bayer and perform the next steps:  

1. Determine the location Julia Bayer was standing
2. Be sure about the location! Find out where she stood, not just the name of the establishment she visited
3. Find out the direction of the sun at that particular moment
4. Read the 'Azimuth' and round it up or down, up to 2 degrees accuracy, making it an even number

Link: [https://www.instagram.com/p/BWt6RzwjPgb](https://www.instagram.com/p/BWt6RzwjPgb/)   
  
The answer is the amount of **degrees**, within a 3 degree accuracy.

### Solution

1. First, from the Instagram post we can see that this image is taken in Berlin. After searching Yandex I found [this](https://fastly.4sqi.net/img/general/600x600/10343441_cVb38vXXGVJBA4EHJqZR3-p5Kuw_T7wfQKaXhB5HoAs.jpg) photo. After checking the [website](https://foursquare.com/v/schillingbr%C3%BCcke/4cb48f021463a1431fdebba9), it appears that the photo is from Schillingbrücke bridge, Mitte, Berlin.
2. Searching for this location in Google, and moving forward in Google maps, we can see that the photo has been taken from Kater Blau. By the traffic sign from the original photo, and the one in Google maps, I have a pretty good idea of where she took the photo from.
3. Going to [suncalc](https://www.suncalc.org), putting the coordinates I found from google maps (52.51178762117033, 13.425500512076356), and going to about 20:00 when sunset is (He wrote What a wonderful evening in the post, and we can see it's a sunset in the phote), the degrees of the sun are 291.39.

Answer: 291