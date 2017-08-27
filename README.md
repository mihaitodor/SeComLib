# SeComLib

**This is a clone of the SeComLib library which I developed during my employment at TU Delft in 2012 - 2013. The original source can be found [here](http://cys.ewi.tudelft.nl/content/secomlib). I am no longer contributing to this project and I am maintaining this clone for archival and documentation purposes.**

The Doxygen-generated documentation from the [doc/html](/doc/html) folder can be viewed [here](https://mihaitodor.github.io/SeComLib/).

## Introduction

### Secure Computation Library (SeComLib)

Secure signal processing (SSP) is a new discipline that merges signal processing and cryptography. The main idea is to protect privacy-sensitive data by using special cryptographic schemes that enable realization of signal processing algorithms in the encrypted domain. Protocols that process data under encryption are published in literature but efficient code is barely available and reusability is a serious issue. This hampers the further uptake of secure signal processing in projects, science, and utilization. Therefore, we have developed a software library that provides a generic framework for realizing secure signal processing applications based on cryptographic techniques. The library contains efficient implementations of cryptographic building blocks for designing secure protocols to help the scientific community with code development.

Providing such a library for fast and efficient implementations of cryptographic protocols may have a great impact in the scientific community. However, the code is not industry-hard, thus commercial products are not likely to be developed directly on the basis of this code. The aim is to impact science by providing a research tool such that secure protocols can be implemented with little effort and to enable collaboration with companies by providing proof of concept examples.

The library has been developed for the Windows and Linux platforms. It is written in C++ and uses the GMP and MPIR libraries for big integer arithmetic.

The library contains cryptographic building blocks such as homomorphic encryption schemes and implementations of signal processing algorithms. More precisely, the Paillier, Okamoto-Uchiyama, DGK, and El Gamal encryption schemes have been implemented. As a vital building block, the library supports data packing, where a number of signal samples are concatenated prior to encryption. The library also has a feature to generate randomizers to be used in the cryptosystems.

Based on the above building blocks, the library provides cryptographic protocols based on the server-client model. The implemented protocols include secure comparison, secure multiplication, secure sign evaluation, etc. These protocols are used to build secure recommender and clustering (K-means and SVM based) systems.

## Details

### Features:

- Multiplatform (Windows and Linux)
- Makes use of the GMP and MPIR libraries for big integer arithmetic, number theoretic operations and random number generation
- Written using robust C++ code, that leverages STL containers and algorithms as much as possible
- Global configuration file in XML format
- Well documented generic classes which can be easily extended

### Building blocks:

- BigInteger wrapper class for the GMP (or MPIR) library, that handles big number arithmetic operations and number theoretic operations. The GMP library can be substituted by any other big number library, as long as the required functionality is implemented.
- Abstract template crypto provider class - a public interface for additive homomrphic cryptosystems:
    - Paillier: Public-Key Cryptosystems Based on Composite Degree Residuosity Classes, Pascal Paillier, 1999
    - Okamoto-Uchiyama: Accelerating Okamoto-Uchiyama's Public-Key Cryptosystem, Jean-Sebastien Coron, David Naccache, and Pascal Paillier, 1999
    - DGK: A correction to "Efficient and Secure Comparison for On-Line Auctions", Ivan Damgard, Martin Geisler, and Mikkel Kroigaard, 2009
    - ElGamal: A Secure and Optimally Efficient Multi-Authority Election Scheme, Ronald Cramer, Rosario Gennaro, Berry Schoenmakers, 1997
- Template data packing class: provides data packing functionality for any of the above mentioned cryptosystems, where a number of signal samples are concatenated prior to encryption
- Randomizer cache: pre-computes a given amount of randomizers for the cryptosystems as well as the ones required by the certain protocols.
- WARNING: At this time, the implementation reuses the randomizers after the cache is exhausted. In a future version, an implementation based on background threads which refill the randomizer caches continuously is desired.

### Simulations:

- "Privacy-Preserving Recommender Systems in eHealth Systems", Arjan Jeckmans, Pieter Hartel, Michael Beye, Zekeriya Erkin, Mihai Todor, Inald Lagendijk, Jeroen Doumen, Tanya Ignatenko, 2013.
    - Secure SVM evaluation for various kernels: linear, polynomial and inverse quadratic RBF
    - Interactive division protocol
    - Interactive sign evaluation protocol
    - Interactive maximum evaluation protocol
    - Client - server mockup implementation
- "Generating Private Recommendations Efficiently Using Homomorphic Encryption and Data Packing", Zekeriya Erkin, Thijs Veugen, Tomas Toft, and Reginald L. Lagendijk, 2012
    - Two versions: with and without data packing
    - Secure Paillier + DGK comparison protocol
    - Secure multiplication protocol
    - Client - server mockup implementation
- Simulation for "Privacy-Preserving Face Recognition", Zekeriya Erkin, Martin Franz, Jorge Guajardo, Stefan Katzenbeisser, Inald Lagendijk, Tomas Toft, 2009 (with speedup enhancements as described in Martin Franz' Master Thesis from 2008)
    - The implementation contains only the Paillier + DGK comparison protocol
    - Client - server mockup implementation
- "Privacy Preserving Processing of Biomedical Signals with Application to Remote Healthcare Systems", Riccardo Lazzeretti, Ph.D Thesis in Information Engineering, University of Siena, 2012
    - Implementation of the secure minimum and maximum selection algorithms
    - Client - server mockup implementation

## For further details and build instructions, please refer to the attached documentation.
