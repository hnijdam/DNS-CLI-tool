# DNS Tool
This script provides information about a domain's DNS records, SSL certificate details, and more.

### Installation ### 


1.1 Install the python requirements with pip

```pip install -r requirements.txt```

#1.2 Clone the repository or download the script:

```git clone https://github.com/hnijdam/DNS-CLI-tool.git```

```cd DNS-CLI-tool/```


#1.3 Make the script executable (if needed):

```chmod +x script.py```


Step 1: Create an Alias for Your Script

Open your terminal.

Edit your shell's configuration file. The configuration file for your shell can be one of the following:

For Bash, it's ~/.bashrc.
For Zsh, it's ~/.zshrc.


Use a text editor like nano or vim to open the configuration file:

For Bash:

```nano ~/.bashrc```

For Zsh:

```nano ~/.zshrc```

Add an alias to your script. An alias is a short command that stands for a longer command. In this case, you're creating an alias called dns-tool that will run your Python script.

For example, if your script is located at /path/to/your/script.py, add the following line to your configuration file:

```alias lookup='python3 /path/to/your/script.py'```


Replace /path/to/your/script.py with the actual path to your Python script.

Save and exit the text editor:

For nano, press Ctrl + O to save, then press Enter, and finally press Ctrl + X to exit.
For vim, press Esc, then type :wq and press Enter.
Apply the changes to your current terminal session or restart your terminal:

For Bash:

```source ~/.bashrc```


For Zsh:

```source ~/.zshrc```


### USAGE ### 

```lookup example.com```

#### LICENCE ###

MIT License

Copyright (c) 2023 Hugo Nijdam

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


