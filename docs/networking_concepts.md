# Networking Concepts

## What is Networking?

A network, in any domain, is the interconnectedness of one or more entities. I say one because it is possible for a network to just have one entity, just take a loopback interface (we'll get to that later). Or the fact that you have a relationship to yourself!

In the world of IT, a network refers to computers and devices with the ability to communicate with each other. But this doesn't happen automatically; through years of innovation, development, and coordination (through human networks), standards for communication have been established so that our devices have the ability to transmit and receive information.

## How Can Computers 'Talk' to Each Other?

Human communication relies on standards and conventions, but flexibility and interpretation exist. For example if I typed: "Hll Rdr, hp y njy th dcmnt wrt," you _might_ be able to parse that I forgot what vowels are and fill in the message. Computers are not capable of the inference you and I have, at least not when it comes to networking concepts. Strict protocols are required. With these standards come models to define what's happening. A popular model for networking is the Open Systems Interconnection (OSI) model. OSI breaks the parts of networking into seven layers, to map over the processes taking place. These are:

- Layer 1: Physical
- Layer 2: Data Link
- Layer 3: Network
- Layer 4: Transport
- Layer 5: Session
- Layer 6: Presentation
- Layer 7: Application

Or as some people remember it from bottom to top as:

- Please Do Not Throw Sausage Pizza Away

Another model is the TCP/IP model, which has four layers:

- Layer 1: Network Interface
- Layer 2: Internet
- Layer 3: Transport
- Layer 4: Application

## How This Project Applies to Networking

This project was created to highlight the protocols that deliver data to and from our devices. Because data seems to magically move from computers, I wanted to investigate how it travels. This project, in inspecting packets, is mostly associated with the Transport and Network layers of the OSI model.

| OSI Layer            | Protocols     | In the app                                               |
| -------------------- | ------------- | -------------------------------------------------------- |
| Layer 2: Data Link   | Ethernet, ARP | ARP in protocol counts; Ethernet header in packet length |
| Layer 3: Network     | IPv4, IPv6    | Source and destination addresses, top hosts              |
| Layer 4: Transport   | TCP, UDP      | Ports, TCP flags, connections and handshakes             |
| Layer 7: Application | DNS, HTTP     | DNS tab, protocol counts                                 |

Each layer wraps its data with a process called encapsulation as it passes information through the stack. A packet, in the OSI model, refers to the Network layer as its unit of data. The Data Link layer uses the term frame, while the Transport layer uses segment for TCP and datagram for UDP.

## Loopback

Now we're looping back to... Loopback. It's where everything a computer sends to itself goes, stays locally. Its addresses are `127.0.0.1` (IPv4) and `::1` (IPv6).

## What This Project Is Not

This project was created to augment my learning about networking. As such, it is not comprehensive and the use of the application should not be considered a perfect representation of all network concepts and implementations. There is the possibility of misattributions, omissions, overcounting, etc. To be blunt, as a learning tool it's not outside the possibility that it makes mistakes in counting your packets.
