/*
SeComLib
Copyright 2012-2013 TU Delft, Information Security & Privacy Lab (http://isplab.tudelft.nl/)

Contributors:
Inald Lagendijk (R.L.Lagendijk@TUDelft.nl)
Mihai Todor (todormihai@gmail.com)
Thijs Veugen (P.J.M.Veugen@tudelft.nl)
Zekeriya Erkin (z.erkin@tudelft.nl)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
/**
@file secure_recommendations/secure_svm.h
@brief Definition of class SecureSvm.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef SECURE_SVM_HEADER_GUARD
#define SECURE_SVM_HEADER_GUARD

//include our headers
#include "utils/config.h"
#include "core/big_integer.h"
#include "core/paillier.h"

//include 3rd party libraries
#include "libsvm/svm.h"
#include "boost/assign.hpp"

//include C++ libraries
#include <iostream>
#include <cmath>
#include <stdexcept>
#include <fstream>
#include <vector>
#include <map>

namespace SeComLib {
using namespace Core;

namespace SecureRecommendations {
	//forward-declare required classes
	class Server;

	/**
	@brief Secure Support Vector Machine algorithm
	*/
	class SecureSvm {
	public:
		/// Define a vector template specialization for vectors of encrypted data
		typedef std::vector<Paillier::Ciphertext> EncryptedVector;

		/// Use this to pass a NULL vector to the Predict method;
		static const EncryptedVector nullVector;

		/// Types of implemented kernels
		enum KernelTypes {linear, homogeneousPolynomial, inhomogeneousPolynomial, inverseQuadraticRBF};

		/// Constructor
		SecureSvm (const std::string &directoryPath, const std::string &modelFile, const PaillierPublicKey &publicKey, const std::weak_ptr<const Server> &server);

		/// Destructor
		~SecureSvm ();

		/// Converts the input string to the proper kernel
		static KernelTypes GetKernel (const std::string &input);

		/// Returns the unsafe classes of safety block SVMs
		const std::string &GetUnsafeClasses () const;

		/// Computes the prediction for a given set of data
		Paillier::Ciphertext Predict (const SecureSvm::EncryptedVector &x, const SecureSvm::EncryptedVector &xx = SecureSvm::nullVector, const SecureSvm::EncryptedVector &xSquared = SecureSvm::nullVector) const;

	private:
		/// The crypto provider
		Paillier cryptoProvider;

		/// A reference to the server - required for interactive protocol requests with the client (secure division)
		std::weak_ptr<const Server> server;

		/// Map kernel names to the kernelTypes enum
		static const std::map<std::string, KernelTypes> kernelTypesMap;

		/// Define an std::vector template specialization for rows of model weights.
		typedef std::vector<BigInteger> ModelVector;

		/// The SVM kernel type
		SecureSvm::KernelTypes kernel;

		/// The name of the model file
		std::string modelFileName;

		/// Contains the trained SVM model. Set this to NULL if the class is constructed with the default constructor
		/// @todo Make this a local variable and wrap it in a std::unique_ptr
		struct svm_model *model;

		/// The scaling applied to the test and model vectors @f$ x_i @f$ and @f$ s_i @f$
		BigInteger featureScalingFactor;

		/// The scaling applied to the SVM parameters, @f$ a_i @f$ and @f$ b @f$ (b is -rho in libsvm)
		/// We want all @f$ a_i @f$ to be > minimumAiValue
		BigInteger svWeightScaling;

		/// The minimum number of relevant decimal digits that @f$ a_i @f$ should preserve
		unsigned short minimumAiDecimalDigits;

		/// The number of digits preserved in the inverse quadratic RBF kernel value after performing the division
		unsigned short inverseQuadraticRbfKernelRelevantDigits;

		/// Scaled 1 - the inverse quadratic RBF kernel numerator
		BigInteger inverseQuadraticRbfNumerator;

		/// The scaling that needs to be applied to the b parameter in order to compensate for the blinding factor added by the interactive protocol which computes the inverse quadratic RBF kernel
		BigInteger blindingFactorScaling;

		/// The scaling applied to the SVM gamma parameter
		BigInteger gammaScaling;

		/// During training, libsvm uses an internal flag to denote the sign of the first label it encounters. If it is negative, we have to invert the sign of f.
		bool reversedSign;

		/// Matrix which stores the scaled @f$ s_i @f$ SVM model vectors
		std::vector<ModelVector> sMatrix;

		/// Matrix which stores the scaled @f$ 2 \gamma s_i @f$ vectors
		std::vector<ModelVector> twoGammaSMatrix;

		/// Matrix which stores the scaled @f$ -2 s_i @f$ vectors
		std::vector<ModelVector> minusTwoSMatrix;

		/// Matrix containing scaled vector product combinations, @f$ 2 \gamma^2 s_i s_j @f$, stored as an unraveled upper triangular matrix on each container matrix row
		std::vector<ModelVector> twoGammaSquaredSSMatrix;

		/// Matrix which stores the encrypted scaled @f$ [s_i^2] @f$ SVM model vectors
		std::vector<EncryptedVector> encryptedSSquaredMatrix;

		/// Vector which stores the scaled @f$ a_i @f$ SVM parameters
		std::vector<BigInteger> aVector;

		/// Stores the scaled and encrypted @f$ b @f$ SVM parameter (-rho in libsvm)
		Paillier::Ciphertext encryptedB;

		/// Stores the scaled gamma SVM parameter (1/(number of attributes) by default)
		BigInteger scaledGamma;

		/// Contains [0], used for optimization purposes
		Paillier::Ciphertext encryptedZero;

		/// [scaled 1], required when computing the inhomogeneous kernel. Precompute it for optimization purposes
		Paillier::Ciphertext encryptedScaledOne;

		/// The prefix of the safety block model files
		std::string safetyModelFilePrefix;

		/// The unsafe classes of the safety block model
		std::string safetyModelUnsafeClasses;

		/// Performs scalings and encryptions
		void preprocessData ();

		/// Computes the linear kernel on encrypted data
		Paillier::Ciphertext linearKernel (const SecureSvm::EncryptedVector &x, const SecureSvm::ModelVector &s) const;

		/// Computes the second degree polynomial kernel on encrypted data
		Paillier::Ciphertext homogeneousPolynomialKernel (const SecureSvm::EncryptedVector &xx, const SecureSvm::ModelVector &twoGammaSquaredSS) const;

		/// Computes the second degree polynomial kernel on encrypted data
		Paillier::Ciphertext inhomogeneousPolynomialKernel (const SecureSvm::EncryptedVector &x, const SecureSvm::EncryptedVector &xx, const SecureSvm::ModelVector &twoGammaS, const SecureSvm::ModelVector &twoGammaSquaredSS) const;

		/// Computes the inverse quadratic RBF kernel d values on encrypted data
		Paillier::Ciphertext computeInverseQuadraticRbfKernelDenominator (const SecureSvm::EncryptedVector &x, const SecureSvm::EncryptedVector &xSquared, const SecureSvm::ModelVector &minusTwoS, const SecureSvm::EncryptedVector &encryptedSSquared) const;

		/// Copy constructor - not implemented
		SecureSvm (SecureSvm const &);

		/// Copy assignment operator - not implemented
		SecureSvm operator= (SecureSvm const &);
	};
}//namespace SecureRecommendations
}//namespace SeComLib

#endif//SECURE_SVM_HEADER_GUARD