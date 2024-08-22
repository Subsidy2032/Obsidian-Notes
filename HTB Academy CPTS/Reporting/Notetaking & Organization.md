## Note Taking Sample Structure

Some of these categories may not be applicable for an application-focused assessment and may even warrant additional categories not listed here.

- Attack path - Outline the path in detail when getting a foothold, compromising one or more hosts (or the AD domain) during an internal penetration test. Use screenshots and command output.
- Credentials - Centralized place for the compromised credentials and secret.
- Findings - Subfolders for findings, writing our narrative and saving it in a folder with any evidence (screenshots, command output). It is also worth keeping a section in your notetaking tool for recording findings information to help organize them for the report.
- Vulnerability Scan Research - A section to take notes on things you've researched and tried with your vulnerability scans (so you don't end up redoing work you already did).
- Service Enumeration Research - A section to take notes on which services you've investigated, failed exploitation attempts, promising vulnerabilities/misconfigurations, etc.
- Web Application Research - A section to note down interesting web applications found through various methods, such as subdomain brute-forcing. It's always good to perform thorough subdomain enumeration externally, scan for common web ports on internal assessments, and run a tool such as Aquatone or EyeWitness to screenshot all applications. As you review the screenshot report, note down applications of interest, common/default credential pairs you tried, etc.
- AD Enumeration Research - A section for showing, step-by-step, what Active Directory enumeration you've already performed. Note down any areas of interest you need to run down later in the assessment.
- OSINT - A section to keep track of interesting information you've collected via OSINT, if applicable to the engagement.
- Administrative Information - Some people may find it helpful to have a centralized location to store contact information for other project stakeholders like Project Managers (PMs) or client Points of Contact (POCs), unique objectives/flags defined in the Rules of Engagement (RoE), and other items that you find yourself often referencing throughout the project. It can also be used as a running to-do list. As ideas pop up for testing that you need to perform or want to try but don't have time for, be diligent about writing them down here so you can come back to them later.
- Scoping Information - Here, we can store information about in-scope IP addresses/CIDR ranges, web application URLs, and any credentials for web applications, VPN, or AD provided by the client. It could also include anything else pertinent to the scope of the assessment so we don't have to keep re-opening scope information and ensure that we don't stray from the scope of the assessment.
- Activity Log - High-level tracking of everything you did during the assessment for possible event correlation.
- Payload Log - Similar to the activity log, tracking the payloads you're using (and a file hash for anything uploaded and the upload location) in a client environment is critical. More on this later.

## Logging

It is essential that we log all scanning and attack attempts and keep raw tool output wherever possible. This will greatly help us come reporting time. Though our notes should be clear and extensive, we may miss something, and having our logs to fallback can help us when either adding more evidence to a report or responding to a client question.

### Exploitation Attempts

[Tmux logging](https://github.com/tmux-plugins/tmux-logging) is an excellent choice for terminal logging, and we should absolutely be using `Tmux` along with logging as this will save every single thing that we type into a Tmux pane to a log file. It is also essential to keep track of exploitation attempts in case the client needs to correlate events later on (or in a situation where there are very few findings and they have questions about the work performed). We can set up Tmux logging on our system as follows:

First, clone the [Tmux Plugin Manager](https://github.com/tmux-plugins/tpm) repo to our.
```shell-session
$ git clone https://github.com/tmux-plugins/tpm ~/.tmux/plugins/tpm
```

Next, create a `.tmux.conf` file in the home directory.
```shell-session
$ touch .tmux.conf
```

The config file should have the following contents:
```shell-session
$ cat .tmux.conf 

# List of plugins

set -g @plugin 'tmux-plugins/tpm'
set -g @plugin 'tmux-plugins/tmux-sensible'
set -g @plugin 'tmux-plugins/tmux-logging'

# Initialize TMUX plugin manager (keep at bottom)
run '~/.tmux/plugins/tpm/tpm'
```

After creating this config file, we need to execute it in our current session, so the settings in the `.tmux.conf` file take effect. We can do this with the [source](https://www.geeksforgeeks.org/source-command-in-linux-with-examples/) command.
```shell-session
$ tmux source ~/.tmux.conf 
```

Next, we can start a new Tmux session (i.e., `tmux new -s setup`).

Once in the session, type `[Ctrl] + [B]` and then hit `[Shift] + [I]` (or `prefix` + `[Shift] + [I]` if you are not using the default prefix key), and the plugin will install (this could take around 5 seconds to complete).

Once the plugin is installed, start logging the current session (or pane) by typing `[Ctrl] + [B]` followed by `[Shift] + [P]` (`prefix` + `[Shift] + [P]`) to begin logging. If all went as planned, the bottom of the window will show that logging is enabled and the output file. To stop logging, repeat the `prefix` + `[Shift] + [P]` key combo or type `exit` to kill the session. Note that the log file will only be populated once you either stop logging or exit the Tmux session.

Once logging is complete, you can find all commands and output in the associated log file.

If we forget to enable Tmux logging and are deep into a project, we can perform retroactive logging by typing `[Ctrl] + [B]` and then hitting `[Alt] + [Shift] + [P]` (`prefix` + `[Alt] + [Shift] + [P]`), and the entire pane will be saved. The amount of saved data depends on the Tmux `history-limit` or the number of lines kept in the Tmux scrollback buffer. If this is left at the default value and we try to perform retroactive logging, we will most likely lose data from earlier in the assessment. To safeguard against this situation, we can add the following lines to the `.tmux.conf` file (adjusting the number of lines as we please):
```shell-session
set -g history-limit 50000
```

Another handy trick is the ability to take a screen capture of the current Tmux window or an individual pane. Let's say we are working with a split window (2 panes), one with `Responder` and one with `ntlmrelayx.py`. If we attempt to copy/paste the output from one pane, we will grab data from the other pane along with it, which will look very messy and require cleanup. We can avoid this by taking a screen capture as follows: `[Ctrl] + [B]` followed by `[Alt] + [P]` (`prefix` + `[Alt] + [P]`). Let's see a quick demo.

Here we can see we're working with two panes. If we try to copy text from one pane, we'll grab text from the other pane, which would make a mess of the output. But, with Tmux logging enabled, we can take a capture of the pane and output it neatly to a file.
![[tmux_pane_capture.gif]]

To recreate the above example first start a new tmux session: `tmux new -s sessionname`. Once in the session type `[Ctrl] + [B]` + `[Shift] + [%]` (`prefix` + `[Shift] + [%]`) to split the panes vertically (replace the `[%]` with `["]` to do a horizontal split). We can then move from pane to pane by typing `[Ctrl] + [B]` + `[O]` (`prefix` + `[O]`).

Finally, we can clear the pane history by typing `[Ctrl] + [B]` followed by `[Alt] + [C]` (`prefix` + `[Alt] + [C]`).

There are many other things we can do with Tmux, customizations we can do with Tmux logging (i.e. [changing the default logging path](https://github.com/tmux-plugins/tmux-logging/blob/master/docs/configuration.md), changing key bindings, running multiple windows within sessions and panes within those windows, etc). It is worth reading up on all the capabilities that Tmux offers and finding out how the tool best fits your workflow. Finally, here are some additional plugins that we like:

- [tmux-sessionist](https://github.com/tmux-plugins/tmux-sessionist) - Gives us the ability to manipulate Tmux sessions from within a session: switching to another session, creating a new named session, killing a session without detaching Tmux, promote the current pane to a new session, and more.
    
- [tmux-pain-control](https://github.com/tmux-plugins/tmux-pain-control) - A plugin for controlling panes and providing more intuitive key bindings for moving around, resizing, and splitting panes.
    
- [tmux-resurrect](https://github.com/tmux-plugins/tmux-resurrect) - This extremely handy plugin allows us to restore our Tmux environment after our host restarts. Some features include restoring all sessions, windows, panes, and their order, restoring running programs in a pane, restoring Vim sessions, and more.
    

Check out the complete [tmux plugins list](https://github.com/tmux-plugins/list) to see if others would fit nicely into your workflow. For more on Tmux, check out this excellent [video](https://www.youtube.com/watch?v=Lqehvpe_djs) by Ippsec and this [cheat sheet](https://mavericknerd.github.io/knowledgebase/ippsec/tmux/) based on the video.

## Artifacts Left Behind

At a minimum, we should be tracking when a payload was used, which host it was used on, what file path it was placed in on the target, and whether it was cleaned up or needs to be cleaned up by the client. A file hash is also recommended for ease of searching on the client's part. It's best practice to provide this information even if we delete any web shells, payloads, or tools.

### Account Creation/System Modification

If we create accounts or modify system settings, it should be evident that we need to track those things in case we cannot revert them once the assessment is complete. Some examples of this include:

- IP address of the host(s)/hostname(s) where the change was made
- Timestamp of the change
- Description of the change
- Location on the host(s) where the change was made
- Name of the application or service that was tampered with
- Name of the account (if you created one) and perhaps the password in case you are required to surrender it

It should go without saying, but as a professional and to prevent creating enemies out of the infrastructure team, you should get written approval from the client before making these types of system modifications or doing any sort of testing that might cause an issue with system stability or availability. This can typically be ironed out during the project kickoff call to determine the threshold beyond which the client is willing to tolerate without being notified.

## Evidence

The report should clearly communicate the issues discovered and evidence that can be used for validation and reproduction.

### What to Capture

As we know, each finding will need to have evidence. It may also be prudent to collect evidence of tests that were performed that were unsuccessful in case the client questions your thoroughness. Capturing your terminal output for significant steps as you go along and tracking that separately alongside your findings is a good idea. For everything else, screenshots should be taken.

### Storage

Much like with our notetaking structure, it's a good idea to come up with a framework for how we organize the data collected during an assessment. This may seem like overkill on smaller assessments, but if we're testing in a large environment and don't have a structured way to keep track of things, we're going to end up forgetting something, violating the rules of engagement, and probably doing things more than once which can be a huge time waster, especially during a time-boxed assessment. Below is a suggested baseline folder structure, but you may need to adapt it accordingly depending on the type of assessment you're performing or unique circumstances.

- `Admin`
    
    - Scope of Work (SoW) that you're working off of, your notes from the project kickoff meeting, status reports, vulnerability notifications, etc
- `Deliverables`
    
    - Folder for keeping your deliverables as you work through them. This will often be your report but can include other items such as supplemental spreadsheets and slide decks, depending on the specific client requirements.
- `Evidence`
    
    - Findings
        - We suggest creating a folder for each finding you plan to include in the report to keep your evidence for each finding in a container to make piecing the walkthrough together easier when you write the report.
    - Scans
        - Vulnerability scans
            - Export files from your vulnerability scanner (if applicable for the assessment type) for archiving.
        - Service Enumeration
            - Export files from tools you use to enumerate services in the target environment like Nmap, Masscan, Rumble, etc.
        - Web
            - Export files for tools such as ZAP or Burp state files, EyeWitness, Aquatone, etc.
        - AD Enumeration
            - JSON files from BloodHound, CSV files generated from PowerView or ADRecon, Ping Castle data, Snaffler log files, CrackMapExec logs, data from Impacket tools, etc.
    - Notes
        - A folder to keep your notes in.
    - OSINT
        - Any OSINT output from tools like Intelx and Maltego that doesn't fit well in your notes document.
    - Wireless
        - Optional if wireless testing is in scope, you can use this folder for output from wireless testing tools.
    - Logging output
        - Logging output from Tmux, Metasploit, and any other log output that does not fit the `Scan` subdirectories listed above.
    - Misc Files
        - Web shells, payloads, custom scripts, and any other files generated during the assessment that are relevant to the project.
- `Retest`
    
    - This is an optional folder if you need to return after the original assessment and retest the previously discovered findings. You may want to replicate the folder structure you used during the initial assessment in this directory to keep your retest evidence separate from your original evidence.

It's a good idea to have scripts and tricks for setting up at the beginning of an assessment. We could take the following command to make our directories and subdirectories and adapt it further.
```shell-session
$ mkdir -p ACME-IPT/{Admin,Deliverables,Evidence/{Findings,Scans/{Vuln,Service,Web,'AD Enumeration'},Notes,OSINT,Wireless,'Logging output','Misc Files'},Retest}
```

## Formatting and Redaction

Credentials and Personal Identifiable Information (`PII`) should be redacted in screenshots and anything that would be morally objectionable, like graphic material or perhaps obscene comments and language. You may also consider the following:

- Adding annotations to the image like arrows or boxes to draw attention to the important items in the screenshot, particularly if a lot is happening in the image (don't do this in MS Word).
    
- Adding a minimal border around the image to make it stand out against the white background of the document.
    
- Cropping the image to only display the relevant information (e.g., instead of a full-screen capture, just to show a basic login form).
    
- Include the address bar in the browser or some other information indicating what URL or host you're connected to.

### Screenshots

Whenever possible we should use terminal output over screenshot. We can mark removed unnecessary output with `<SNIP>`. but never alter output or add things that were not in the original command or output. It's also important that the source material that you're pasting _from_ has all formatting stripped before going into your Word document. It may cause the command not to work when the client tries to reproduce.

We should avoid using tools by pixelation or blurring with tools like Greenshot. [Research](https://www.bleepingcomputer.com/news/security/researcher-reverses-redaction-extracts-words-from-pixelated-image/) has shown that the original data likely can be recovered by reversing the pixelation/blurring technique. This can be done with a tool such as [Unredacter](https://github.com/bishopfox/unredacter). Instead we should use black bars (or another solid shape), the image should be edited directly, and not add a shape through MS word. In the same way we can't rely on HTML/CSS styling to obscure sensitive data that we publish on the web.

Finally, here is a suggested way to present terminal evidence in a report document. Here we have preserved the original command and output but enhanced it to highlight both the command and the output of interest (successful authentication).
![[terminal_output.webp]]

The way we present evidence will differ from report to report. We may be in a situation where we cannot copy/paste console output, so we must rely on a screenshot. The tips here are intended to provide options for creating a neat but accurate report with all evidence represented adequately.

### Terminal

Typically the only thing that needs to be redacted from terminal output is credentials (whether in the command itself or the output of the command). With password hashes we can usually leave the first and last 3 or 4 characters to show there was actually a hash there. For cleartext credentials or any other human-readable content that needs to be obfuscated, you can just replace it with a `<REDACTED>` or `<PASSWORD REDACTED>` placeholder, or similar.

You should also consider color-coded highlighting in your terminal output to highlight the command that was run and the interesting output from running that command. This enhances the reader's ability to identify the essential parts of the evidence and what to look for if they try to reproduce it on their own.

## What Not to Archive

When starting a penetration test, we are being trusted by our customers to enter their network and "do no harm" wherever possible. This means not bringing down any hosts or affecting the availability of applications or resources, not changing passwords (unless explicitly permitted), making significant or difficult-to-reverse configuration changes, or viewing or removing certain types of data from the environment. This data may include unredacted PII, potentially criminal info, anything considered legally "discoverable," etc. For example, if you gain access to a network share with sensitive data, it's probably best to just screenshot the directory with the files in it rather than opening individual files and screenshotting the file contents. If the files are as sensitive as you think, they'll get the message and know what's in them based on the file name. Collecting actual PII and extracting it from the target environment may have significant compliance obligations for storing and processing that data like GDPR and the like and could open up a slew of issues for our company and us.