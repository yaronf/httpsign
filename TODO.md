* Code TODOs
* Field matching should start with covered components (order matters!), components that are not found result in an error.
* Separate test cases for specialty components.
* Test case for HTTP/2.
* Check MUSTs and SHOULDs.
* Add verification requirements, Sec. 3.2.1.
* Fuzz tests.

# Draft comments
* Security Considerations: implementations must be robust against attacks that introduce headers with a "@" prefix.
* Test vectors: the ones for PSS don't make sense, because RSA-PSS signatures are random.
* 3 pipeline symbols at the end of lines in 2.1.2 appear to be typos
* 