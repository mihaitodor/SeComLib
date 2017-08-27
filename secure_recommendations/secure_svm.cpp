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
@file secure_recommendations/secure_svm.cpp
@brief Implementation of class SecureSvm.
@details Secure Support Vector Machine implementation
@author Mihai Todor (todormihai@gmail.com)
*/

#include "secure_svm.h"
//avoid circular includes
#include "server.h"

namespace SeComLib {
namespace SecureRecommendations {
	/**
	Initialize the nullVector instance
	*/
	const SecureSvm::EncryptedVector SecureSvm::nullVector;

	/**
	Initialize the kernel types map
	*/
	const std::map<std::string, SecureSvm::KernelTypes> SecureSvm::kernelTypesMap = boost::assign::map_list_of("linear", SecureSvm::linear)
																												("homogeneous_poly", SecureSvm::homogeneousPolynomial)
																												("inhomogeneous_poly", SecureSvm::inhomogeneousPolynomial)
																												("rbf", SecureSvm::inverseQuadraticRBF);

	/**
	Sets configuration parameters.

	Sets the path to the configuration file and parses it.

	Extracts the unsafe classes in the case of safety model files

	@param directoryPath the absolute path to the model file
	@param modelFile the model file
	@param publicKey the client public key
	@param server a pointer reference to the server instance
	*/
	SecureSvm::SecureSvm (const std::string &directoryPath, const std::string &modelFile, const PaillierPublicKey &publicKey, const std::weak_ptr<const Server> &server) : cryptoProvider(publicKey), server(server), modelFileName(modelFile), model(NULL) {
		//set configuration parameters
		this->featureScalingFactor = BigInteger(10).Pow(Utils::Config::GetInstance().GetParameter<unsigned long>("SecureRecommendations.Svm.minimumFeatureDecimalDigits"));
		this->minimumAiDecimalDigits = Utils::Config::GetInstance().GetParameter<unsigned short>("SecureRecommendations.Svm.minimumAiDecimalDigits");

		//set the kernel
		this->kernel = SecureSvm::GetKernel(Utils::Config::GetInstance().GetParameter<std::string>("SecureRecommendations.kernel"));

		//set the safety block models specific parameters
		this->safetyModelFilePrefix = Utils::Config::GetInstance().GetParameter<std::string>("SecureRecommendations.Server.SafetyBlock.modelFilePrefix");

		//parse the unsafe classes for the safety models
		if (std::string::npos != this->modelFileName.find(this->safetyModelFilePrefix)) {
			std::vector<unsigned short> unsafeClasses;
			//iterate over each class (digit) in the file name
			for (size_t i = this->safetyModelFilePrefix.size(); i <  this->modelFileName.find("."); ++i) {
				//the difference between any digit and '0' will yield the desired numeric value
				unsafeClasses.emplace_back(this->modelFileName[i] - '0');
			}

			std::sort(unsafeClasses.begin(), unsafeClasses.end());

			//convert the ordered unsafeClasses vector to a stringstream
			std::stringstream unsafeClassesStream;
			for (std::vector<unsigned short>::const_iterator unsafeClassesIterator = unsafeClasses.begin(); unsafeClassesIterator != unsafeClasses.end(); ++unsafeClassesIterator) {
				unsafeClassesStream << *unsafeClassesIterator;
			}
			this->safetyModelUnsafeClasses = unsafeClassesStream.str();
		}

		//get the inverse quadratic RBF kernel configuration parameters
		if (SecureSvm::inverseQuadraticRBF == this->kernel) {
			this->inverseQuadraticRbfKernelRelevantDigits = Utils::Config::GetInstance().GetParameter<unsigned short>("SecureRecommendations.Svm.inverseQuadraticRbfKernelRelevantDigits");

			unsigned long blindingFactorSize = Utils::Config::GetInstance().GetParameter<unsigned long>("SecureRecommendations.Server.blindingFactorSize");
			this->blindingFactorScaling = BigInteger(2).Pow(blindingFactorSize + 1);//the maximum value of the blinding may have blindingFactorSize + 1 bits
		}

		std::string modelFilePath = directoryPath + this->modelFileName;

		std::ifstream fileStream(modelFilePath);

		//test if the file exists and can be accessed
		if (!fileStream.good()) {
			throw std::runtime_error("Can't open the SVM model file.");
		}

		/// Compute the gamma scaling (the linear kernel does not use gamma)
		if (SecureSvm::linear != this->kernel) {
			//we must read the gamma parameter from the file as a string, to determine the scaling that needs to be applied to it, such that it ends up being > 0 and we don't loose precision
			std::string line;
			bool foundGamma = false;
			while (std::getline(fileStream, line)) {
				if (std::string::npos != line.find("gamma")) {
					//we only scale gamma if it has a radix point
					if (std::string::npos != line.find('.')) {
						std::string gammaValueString = line.substr(line.find(' '));
						std::stringstream gammaValueStream; gammaValueStream << gammaValueString;
						double gammaValue; gammaValueStream >> gammaValue;

						//if gamma has decimals, then it *must* be a negative power of 2...
						double exponent = std::log(gammaValue) / std::log(2.0);
						if (exponent > 0) throw std::runtime_error("Unexpected gamma value detected.");
						
						//we want to compute the scaling such that gamma * scaling = 1
						//first, we round the negative number towards the closest integer
						this->gammaScaling = BigInteger(2).Pow(static_cast<unsigned long>(std::abs(std::ceil(exponent - 0.5))));
					}
					else {
						//gamma is already an integer
						this->gammaScaling = 1;
					}

					foundGamma = true;
					break;
				}
			}
			//sanity check
			if (!foundGamma)
				throw std::runtime_error("Can't find gamma in the model file.");
		}

		//close the file stream
		fileStream.close();

		//use the libsvm library to parse the model file
		this->model = svm_load_model(modelFilePath.c_str());

		if (NULL == this->model) {
			throw std::runtime_error("Invalid model file.");
		}

		this->preprocessData();

		std::cout << "Loaded " << modelFile << "; nSV: " << this->model->l << std::endl;
	}

	/**
	Releases the SVM model data
	*/
	SecureSvm::~SecureSvm () {
		svm_free_and_destroy_model(&this->model);
	}

	/**
	@param input a string containing the name of the kernel
	@return The kernel
	@throw std::runtime_error Invalid kernel name received.
	*/
	SecureSvm::KernelTypes SecureSvm::GetKernel (const std::string &input) {
		std::map<std::string, KernelTypes>::const_iterator iterator = SecureSvm::kernelTypesMap.find(input);

		//if the specified kernel name is not found
		if (SecureSvm::kernelTypesMap.end() == iterator) {
			///@todo Throw a custom exception here
			throw std::runtime_error("Invalid kernel name received.");
		}

		return iterator->second;
	}

	/**
	@return A vector of unsafe classes
	*/
	const std::string &SecureSvm::GetUnsafeClasses () const {
		return this->safetyModelUnsafeClasses;
	}

	/**
	Evaluates the encrypted prediction function, @f$ [f(x)] @f$

	@f$ f(x) = \sum_{i=1}^t (c_i \cdot a_i \cdot K_i) + b @f$

	Scaled prediction function: @f$ f(x)^* = \sum_{i=1}^t (c_i \cdot a_i^* \cdot sc_a \cdot K_i) + b^* \cdot sc_a \cdot sc_b @f$

	Encrypted scaled prediction function: @f$ [f(x)^*] = \prod_{i=1}^t ([K_i]^{c_i \cdot a_i^* \cdot sc_a}) \cdot [b^* \cdot sc_a \cdot sc_b] @f$

	Where @f$ a_i^* = \frac{a_i}{m} @f$, @f$ b^* = \frac{b}{m} @f$ and @f$ m = min(min(a_i), b) @f$. Also, @f$ t @f$ is the number of SV.
	
	If the sign of the labels produced by libsvm is reversed, then the signs of @f$ a_i @f$ and @f$ b @f$ are reversed during preprocessing. See preprocessData() for details.
	
	@param x the encrypted attribute vector
	@param xx the encrypted attribute vector product combinations, @f$ x_i x_j @f$, stored as an unraveled upper triangular matrix (defaults to SecureSvm::nullVector)
	@param xSquared the encrypted squared attribute vector (defaults to SecureSvm::nullVector)
	@return The encrypted value of the kernel
	@throw std::runtime_error Invalid kernel type.
	*/
	Paillier::Ciphertext SecureSvm::Predict (const SecureSvm::EncryptedVector &x, const SecureSvm::EncryptedVector &xx, const SecureSvm::EncryptedVector &xSquared) const {
		/// Initialize the accumulator with [0] for the homomorphic addition to work!!!
		Paillier::Ciphertext output = this->encryptedZero;

		//stores the values for the inverse quadratic RBF kernel
		SecureSvm::EncryptedVector inverseQuadraticRbfKernelValues;

		//iterate over the model rows (vectors)
		for (size_t i = 0; i < this->aVector.size(); ++i) {
			Paillier::Ciphertext encryptedKernelValue;

			//compute kernel
			switch (this->kernel) {
				case SecureSvm::linear:
					encryptedKernelValue = this->linearKernel(x, this->sMatrix[i]);
					break;
				case SecureSvm::homogeneousPolynomial:
					encryptedKernelValue = this->homogeneousPolynomialKernel(xx, this->twoGammaSquaredSSMatrix[i]);
					break;
				case SecureSvm::inhomogeneousPolynomial:
					encryptedKernelValue = this->inhomogeneousPolynomialKernel(x, xx, this->twoGammaSMatrix[i], this->twoGammaSquaredSSMatrix[i]);
					break;
				case SecureSvm::inverseQuadraticRBF:
					/// Compute @f$ (1 + c d) @f$ for the inverse quadratic RBF kernel and use an interactive protocol to produce the actual kernel values
					inverseQuadraticRbfKernelValues.emplace_back(this->computeInverseQuadraticRbfKernelDenominator(x, xSquared, this->minusTwoSMatrix[i], encryptedSSquaredMatrix[i]));
					break;
				default:
					/// @todo Throw a custom error here
					throw std::runtime_error("Invalid kernel type.");
			}
			
			/// Compute @f$ \prod_i{([K(s_i, x)]^{a_i})} @f$

			//compute this separately for the inverse quadratic RBF kernel
			if (SecureSvm::inverseQuadraticRBF != this->kernel) {
				output = output + encryptedKernelValue * this->aVector[i];
			}
		}

		/// The inverse quadratic RBF kernel requires an interactive protocol to compute the kernel values
		if (SecureSvm::inverseQuadraticRBF == this->kernel) {
			/// Interact with the client to compute @f$ [K] = [1 / denominator] @f$

			//debug
			//std::cout << "numerator:" << this->inverseQuadraticRbfNumerator.ToString(10) << std::endl;

			//replace the denominator values with the actual kernel values
			this->server.lock()->InteractiveSecureDivision(this->inverseQuadraticRbfNumerator, inverseQuadraticRbfKernelValues);

			for (size_t i = 0; i < this->aVector.size(); ++i) {
				//debug
				//this->server.lock()->DebugValue(inverseQuadraticRbfKernelValues[i]);
				//std::cout << this->aVector[i].ToString(10).c_str() << std::endl;

				output = output + inverseQuadraticRbfKernelValues[i] * this->aVector[i];

				//debug
				//this->server.lock()->DebugValue(this->cryptoProvider.HomomorphicMultiply(inverseQuadraticRbfKernelValues[i], this->aVector[i]));
				//this->server.lock()->DebugValue(output);
			}

			//debug
			//this->server.lock()->DebugValue(output);
			//this->server.lock()->DebugValue(this->encryptedB);
		}

		output = output + this->encryptedB;

		//debug
		//this->server.lock()->DebugValue(output);

		return output;
	}

	/**
	Preprocess the SVM model parameters and vectors required for computing f

	@throw std::runtime_error Computed scaling is too large.
	*/
	void SecureSvm::preprocessData () {
		/// If the training file has a negative value as the first label, then we need to invert the sign of the a and b model parameters.
		/// Details here: http://www.csie.ntu.edu.tw/~cjlin/libsvm/faq.html#f430
		if (this->model->label[0] < 0)
			this->reversedSign = true;
		else
			this->reversedSign = false;

		/// Scale the gamma parameter
		//model->param.gamma is unitialized in the case of the linear kernel and it's not used in the formula
		if (SecureSvm::linear != this->kernel) {
			this->scaledGamma = BigInteger(this->model->param.gamma, this->gammaScaling);
			
			//debug
			//std::cout << this->scaledGamma.ToString(10).c_str() << std::endl;
			//std::cout << this->gammaScaling.ToString(10).c_str() << std::endl;
		}

		/// Determine the amount of scaling which needs to be applied to @f$ a_i @f$
		this->svWeightScaling = BigInteger(10).Pow(static_cast<unsigned long>(this->minimumAiDecimalDigits));

		//std::cout << this->svWeightScaling.ToString(10).c_str() << std::endl;

		/// Since @f$ f(x) = \sum_i{a_i K(s_i, x)} + b @f$ and we are only interested in the sign of @f$ f @f$, we can divide both @f$ a_i @f$ and @f$ b @f$ by @f$ \min(|a_i|, |b|) @f$ such that the smallest value becomes 1
		double minAbsAi = std::abs(this->model->sv_coef[0][0]);
		for (unsigned int i = 1; i < static_cast<unsigned int>(this->model->l); ++i) {
			if (minAbsAi > std::abs(this->model->sv_coef[0][i])) {
				minAbsAi = std::abs(this->model->sv_coef[0][i]);
			}
		}
		//compute the minimum between min(a_i) and b
		double minAbsAiB = minAbsAi;
		if (minAbsAi > std::abs(this->model->rho[0])) {
			minAbsAiB = std::abs(this->model->rho[0]);
		}

		//debug
		//std::cout << minAbsAiB << std::endl;

		/// Scale the @f$ a_i @f$ parameters
		//iterate over the model rows (vectors)
		for (unsigned int i = 0; i < static_cast<unsigned int>(this->model->l); ++i) {
			/// We need to check if the sign of the prediction needs to be inverted.
			//double aValue = this->reversedSign ? -this->model->sv_coef[0][i]: this->model->sv_coef[0][i];
			double aValue = this->reversedSign ? -this->model->sv_coef[0][i] / minAbsAiB : this->model->sv_coef[0][i] / minAbsAiB;
			this->aVector.emplace_back(BigInteger(aValue, this->svWeightScaling));

			//debug
			/*
			if (this->aVector.back() > this->cryptoProvider.GetMessageSpaceUpperBound() / 2) {
				std::cout << "-" << (this->cryptoProvider.GetMessageSpaceUpperBound() - this->aVector.back()).ToString(10).c_str() << std::endl;
			}
			else
				std::cout << this->aVector.back().ToString(10).c_str() << std::endl;
			*/
		}

		/// Scale and encrypt the @f$ b @f$ parameter
		
		//construct the scaling for b (see the description of each kernel for the detailed formulas)
		BigInteger bScaling(this->svWeightScaling);//apply the SVM parameter scaling (to compensate for the scaling applied to a_i)
		
		//compensate for scalings applied to s_i and x_i
		switch (this->kernel) {
			case SecureSvm::linear:
				//compensate for s_i * x_i
				bScaling *= this->featureScalingFactor;
				bScaling *= this->featureScalingFactor;
				break;
			case SecureSvm::homogeneousPolynomial:
			case SecureSvm::inhomogeneousPolynomial:
				//compensate for (gamma s_i * x_i)^2 or (gamma s_i * x_i + 1)^2
				bScaling *= this->gammaScaling;
				bScaling *= this->gammaScaling;
				bScaling *= this->featureScalingFactor;
				bScaling *= this->featureScalingFactor;
				bScaling *= this->featureScalingFactor;
				bScaling *= this->featureScalingFactor;
				break;
			case SecureSvm::inverseQuadraticRBF:
				//compensate for the digits preserved from the kernel value
				bScaling *= BigInteger(10).Pow(static_cast<unsigned long>(this->inverseQuadraticRbfKernelRelevantDigits));
				//compensate for the secure division blinding factor
				bScaling *= this->blindingFactorScaling;
				break;
			default:
				/// @todo Throw a custom error here
				throw std::runtime_error("Invalid kernel type.");
		}

		//remap negative values to the upper part of the crypto provider message space
		//libsvm negates rho before adding it to the sum. We also need to check if the sign of the prediction needs to be inverted
		//double bValue = this->reversedSign ? this->model->rho[0] : -(this->model->rho[0]);
		double bValue = this->reversedSign ? this->model->rho[0] / minAbsAiB : -(this->model->rho[0] / minAbsAiB);
		BigInteger scaledB = BigInteger(bValue, bScaling);
		
		//encrypt scaled b
		this->encryptedB = this->cryptoProvider.EncryptInteger(scaledB);

		//debug
		//std::cout this->svWeightScaling.ToString(10).c_str() << std::endl;
		//this->server.lock()->DebugValue(this->encryptedB);
		
		/// Precompute the scaled model vector factors
		BigInteger two(2);
		BigInteger gammaSquared = this->scaledGamma.GetPow(2);
		//iterate over the model rows (vectors)
		for (unsigned int row = 0; row < static_cast<unsigned int>(this->model->l); ++row) {
			/// Temporary vector containing scaled model weights
			SecureSvm::ModelVector tempS;

			/// Temporary vector containing scaled @f$ 2 \gamma * s_i @f$
			SecureSvm::ModelVector tempTwoGammaS;

			/// Temporary vector containing scaled @f$ -2 s_i @f$
			SecureSvm::ModelVector tempMinusTwoS;

			/// Polynomial kernel => need to compute the weight combinations, @f$ s_i s_j @f$, of the model, stored as an unraveled upper triangular matrix.
			/// We also multiply them by two (when @f$ i \neq j @f$), because @f$ s_i s_j = s_j s_i @f$ (see the polynomial kernels implementation for details).
			/// We also multiply the products by @f$ \gamma^2 @f$.
			SecureSvm::ModelVector tempTwoGammaSquaredSS;

			/// Inverse quadratic RBF kernel => need to compute @f$ [s_i^2] @f$
			SecureSvm::EncryptedVector tempEncryptedSSquared;

			//create an iterator for the model row (vector)
			svm_node *iterator = this->model->SV[row];

			//collect all the weights for the current row (vector)
			//libsvm implementation detail: iterator->index is set to -1 after the last attribute weight in the vector
			//we assume that no attribute weights are omitted in the model file (the format specifies that 0 valued weights can be omitted)
			while (-1 != iterator->index) {
				//scale the current value and load it in a buffer variable
				BigInteger tempSValue(iterator->value, this->featureScalingFactor);

				//we need to have values greater than 0 in order to ensure security
				if (tempSValue == 0) {
					tempSValue = 1;
				}

				//debug
				//std::cout << tempSValue.ToString(10) << std::endl;

				tempS.push_back(tempSValue);

				++iterator;
			}

			//s matrix is needed only for the linear kernel
			if (SecureSvm::linear == this->kernel) {
				//populate the s matrix
				this->sMatrix.emplace_back(tempS);
			}

			//compute auxiliary matrices for the polynomial and RBF kernels
			if (SecureSvm::linear != this->kernel) {
				for (size_t i = 0; i < tempS.size(); ++i) {
					//twoGammaSquaredSS matrix is not required for the inverse quadratic RBF kernel
					if (SecureSvm::inverseQuadraticRBF != this->kernel) {
						for (size_t j = i; j < tempS.size(); ++j) {
							/// W A R N I N G!!! DO NOT multiply the diagonal with 2! (see the polynomial kernels implementation for details)
							if (i != j) {
								tempTwoGammaSquaredSS.push_back(two * gammaSquared * tempS[i] * tempS[j]);
							}
							else {
								tempTwoGammaSquaredSS.push_back(gammaSquared * tempS[i] * tempS[j]);
							}
						}
					}

					/// Compute the @f$ 2 \gamma * s_i @f$ factor for inhomogeneous polynomial, SCALED ACCORDINGLY
					/// (see the inhomogeneous polynomial kernel implementation for details on the required scaling)
					if (SecureSvm::inhomogeneousPolynomial == this->kernel) {
						//get local copy of the current scaled value
						BigInteger tempSValue = tempS[i];

						//need to compensate for gamma^2 * x^2 * s^2
						//we already have gammaScaling * featureScalingFactor, so we add the rest
						tempSValue *= this->gammaScaling;
						tempSValue *= this->featureScalingFactor;
						tempSValue *= this->featureScalingFactor;
						tempTwoGammaS.push_back(two * this->scaledGamma * tempSValue);
					}

					//encrypted sSquared and minusTwoS matrices are required only for the inverse quadratic RBF kernel
					if (SecureSvm::inverseQuadraticRBF == this->kernel) {
						/// Compute the @f$ s_i^2 @f$ factors
						tempEncryptedSSquared.push_back(this->cryptoProvider.EncryptInteger(tempS[i].GetPow(2)));

						/// Compute the @f$ -2 s_i @f$ factors
						tempMinusTwoS.push_back(-two * tempS[i]);//use unary - operator
					}
				}

				//twoGammaSquaredSS matrix is not requred for the inverse quadratic RBF kernel
				if (SecureSvm::inverseQuadraticRBF != this->kernel) {
					this->twoGammaSquaredSSMatrix.emplace_back(tempTwoGammaSquaredSS);
				}

				//twoGammaS matrix is required for the inhomogeneous polynomial kernel
				if (SecureSvm::inhomogeneousPolynomial == this->kernel) {
					this->twoGammaSMatrix.emplace_back(tempTwoGammaS);
				}

				//minusTwoS and encryptedSSquared matrices are required for the inverse quadratic RBF kernel
				if (SecureSvm::inverseQuadraticRBF == this->kernel) {
					this->minusTwoSMatrix.emplace_back(tempMinusTwoS);

					this->encryptedSSquaredMatrix.emplace_back(tempEncryptedSSquared);
				}
			}
		}//model rows

		/// Compute [scaled 1] for the inhomogeneous polynomial kernel
		if (SecureSvm::inhomogeneousPolynomial == this->kernel) {
			BigInteger one(1);
			//need to compensate for gamma^2 * x^2 * s^2
			one *= this->gammaScaling;
			one *= this->gammaScaling;
			one *= this->featureScalingFactor;
			one *= this->featureScalingFactor;
			one *= this->featureScalingFactor;
			one *= this->featureScalingFactor;
			this->encryptedScaledOne = this->cryptoProvider.EncryptInteger(one);
		}

		
		if (SecureSvm::inverseQuadraticRBF == this->kernel) {
			/// Compute [scaled 1] for the inverse quadratic RBF kernel denominator
			BigInteger one(1);
			//need to compensate for gamma * (x - s)^2
			one *= this->gammaScaling;
			one *= this->featureScalingFactor;
			one *= this->featureScalingFactor;
			this->encryptedScaledOne = this->cryptoProvider.EncryptInteger(one);

			/// Scale the divisor of the interactive division protocol for the inverse quadratic RBF kernel
			this->inverseQuadraticRbfNumerator = BigInteger(1);
			//compensate for the random blinding
			this->inverseQuadraticRbfNumerator *= this->blindingFactorScaling;
			//compensate for gamma * (x - s)^2
			this->inverseQuadraticRbfNumerator *= this->gammaScaling;
			this->inverseQuadraticRbfNumerator *= this->featureScalingFactor;
			this->inverseQuadraticRbfNumerator *= this->featureScalingFactor;
			//preserve the required number of digits after performing division
			this->inverseQuadraticRbfNumerator *= BigInteger(10).Pow(static_cast<unsigned long>(inverseQuadraticRbfKernelRelevantDigits));
		}

		/// Precompute [0] for optimization purposes
		this->encryptedZero = this->cryptoProvider.GetEncryptedZero();
	}

	/**
	Linear kernel: @f$ K_i = \sum_{j=1}^f(x_j \cdot s_{i,j}) @f$

	Scaled linear kernel: @f$ K_i^* = \sum_{j=1}^f(x_j \cdot sc_f \cdot s_{i,j} \cdot sc_f) @f$

	Encrypted scaled linear kernel: @f$ [K_i^*] = \prod_{j=1}^f([x_j \cdot sc_f]^{s_{i,j} \cdot sc_f}) $@f$ and $@f$ sc_b = sc_f^2 @f$

	@param x the encrypted attribute vector
	@param s a model vector
	@return The encrypted value of the kernel
	*/
	Paillier::Ciphertext SecureSvm::linearKernel (const SecureSvm::EncryptedVector &x, const SecureSvm::ModelVector &s) const {
		/// Initialize the accumulator with [0] for the homomorphic addition to work!!!
		Paillier::Ciphertext output = this->encryptedZero;

		for (size_t i = 0; i < s.size(); ++i) {
			//debug
			/*
			this->server.lock()->DebugValue(x[i]);
			std::cout << s[i].ToString(10) << std::endl;
			*/
			output = output + x[i] * s[i];
		}
		
		return output;
	}

	/**
	Homogeneous polynomial kernel: @f$ K_i = (\gamma \sum_{j=1}^f(x_j \cdot s_{i,j}))^2 @f$ (where @f$ \gamma = 1 @f$)

	Scaled homogeneous polynomial kernel: @f$ K_i^* = (\sum_{j=1}^f(x_j \cdot sc_f \cdot s_{i,j} \cdot sc_f))^2 @f$

	Encrypted scaled homogeneous polynomial kernel: @f$ [K_i^*] = \prod_{j=1}^{f-1} \prod_{k=j+1}^{f}[x_j \cdot x_k \cdot sc_f^2]^{2 \cdot s_{i,j} \cdot s_{i,k} \cdot sc_f^2}) \cdot \prod_{j=1}^f([x^2_j \cdot sc_f^2]^{s^2_{i,j} \cdot sc_f^2}) @f$ and @f$ sc_b = sc_f^4 @f$

	Since @f$ x_i x_j = x_j x_i @f$ and @f$ s_i s_j = s_j s_i @f$, the diagonal elements are taken into account only once!

	@param xx the encrypted attribute vector product combinations, @f$ x_i x_j @f$, stored as an unraveled upper triangular matrix
	@param twoGammaSquaredSS the model weights vector product combinations, @f$ 2 \gamma^2 s_i s_j @f$, where @f$ i \neq j @f$ and @f$ \gamma^2 s_i s_j @f$, where @f$ i = j @f$, stored as an unraveled upper triangular matrix
	@return The encrypted value of the kernel
	*/
	Paillier::Ciphertext SecureSvm::homogeneousPolynomialKernel (const SecureSvm::EncryptedVector &xx, const SecureSvm::ModelVector &twoGammaSquaredSS) const {
		/// Initialize the accumulator with [0] for the homomorphic addition to work!
		Paillier::Ciphertext output = this->encryptedZero;

		for (size_t i = 0; i < xx.size(); ++i) {
			output = output + xx[i] * twoGammaSquaredSS[i];
		}
	
	#if 0
		/* previous algorithm with complex index logic. Now, we just do sum(2*(xi xj)(si sj)) if i != j and sum((xi xj)(si sj)) if i==j in the encrypted domain */

		for (size_t i = 0; i < s.size(); ++i) {
			for (size_t j = 0; j < s.size(); ++j) {
				//the x_ix_j matrix is unraveled into a vector, xx, so we need to compute the apropriate index
				//basically, we need to subtract sum(i - 1) = (i - 1) * i / 2 at each step to determine the index in the vector
				size_t index;
				if (i <= j) {
					//the upper triangle of the x_ix_j matrix
					index = i * (s.size() - 1) - (i - 1) * i / 2 + j;
				}
				else {
					//the lower triangle of the x_ix_j matrix is symmetric to the upper one, so we remap it there
					index = j * (s.size() - 1) - (j - 1) * j / 2 + i;
					
				}

				//std::cout << "i: " << i << "; j: " << j << "; index: " << index << std::endl;

				output = output + xx[index] * ss[index];
			}
		}
	#endif
		
		return output;
	}

	/**
	Inhomogeneous polynomial kernel: @f$ K_i = (\gamma \sum_{j=1}^f(x_j \cdot s_{i,j}) + 1)^2 @f$

	Scaled inhomogeneous polynomial kernel: @f$ K_i^* = (\gamma \cdot sc_{\gamma} \sum_{j=1}^f(x_j \cdot sc_f \cdot s_{i,j} \cdot sc_f) + sc_{\gamma} \cdot sc_f^2)^2 @f$

	Encrypted scaled inhomogeneous polynomial kernel: @f$ [K_i^*] = (\prod_{j=1}^{f-1} \prod_{k=j+1}^{f}([x_j \cdot x_k \cdot sc_f^2]^{2 \cdot \gamma^2 \cdot sc_{\gamma}^2 \cdot s_{i,j} \cdot s_{i,k} \cdot sc_f^2})) \cdot (\prod_{j=1}^f([x^2_j \cdot sc_f^2]^{\gamma^2 \cdot sc_{\gamma}^2 \cdot s^2_{i,j} \cdot sc_f^2})) \cdot (\prod_{j=1}^f([x_j \cdot sc_f]^{2 \cdot \gamma \cdot sc_{\gamma}^2 \cdot s_{i,j} \cdot sc_f^3})) \cdot [sc_{\gamma}^2 \cdot sc_f^4] @f$ and @f$ sc_b = sc_{\gamma}^2 \cdot sc_f^4 @f$

	Since @f$ x_i x_j = x_j x_i @f$ and @f$ s_i s_j = s_j s_i @f$, the diagonal elements are taken into account only once!

	@param x the encrypted attribute vector
	@param xx the encrypted attribute vector product combinations, @f$ x_i x_j @f$, stored as an unraveled upper triangular matrix
	@param twoGammaS scaled @f$ 2 \gamma s_i @f$
	@param twoGammaSquaredSS the model weights vector product combinations, @f$ 2 \gamma^2 s_i s_j @f$, where @f$ i \neq j @f$ and @f$ \gamma^2 s_i s_j @f$, where @f$ i = j @f$, stored as an unraveled upper triangular matrix
	@return The encrypted value of the kernel
	*/
	Paillier::Ciphertext SecureSvm::inhomogeneousPolynomialKernel (const SecureSvm::EncryptedVector &x, const SecureSvm::EncryptedVector &xx, const SecureSvm::ModelVector &twoGammaS, const SecureSvm::ModelVector &twoGammaSquaredSS) const {
		//leverage the homogeneousPolynomialKernel and linearKernel implementations to simplify the formula
		return this->homogeneousPolynomialKernel(xx, twoGammaSquaredSS) + this->linearKernel(x, twoGammaS) + this->encryptedScaledOne;
	}

	/**
	Computes the encrypted denominator of the inverse quadratic RBF kernel.

	Inverse quadratic RBF kernel: @f$ K_i = \frac{1}{r \cdot (1 + \gamma (\sum_{j=1}^f(x_j - s_{i,j})^2))} @f$

	Scaled inverse quadratic RBF kernel: @f$ K_i^* = \frac{r \cdot sc_{\gamma} \cdot sc_f^2 \cdot sc_r \cdot sc_k}{r \cdot (sc_{\gamma} \cdot sc_f^2 + \gamma \cdot sc_{\gamma} (\sum_{j=1}^f(x_j \cdot sc_f - s_{i,j} \cdot sc_f)^2))} @f$

	Encrypted scaled inverse quadratic RBF kernel: @f$ [K_i^*] = \left[\frac{r \cdot sc_{\gamma} \cdot sc_f^2 \cdot sc_r \cdot sc_k}{d_i^*}\right] @f$

	Where @f$ [d_i^*] = \left([sc_{\gamma} \cdot sc_f^2] \cdot \left(\prod_{j=1}^f([x_j^2 \cdot sc_f^2] \cdot [x_j \cdot sc_f]^{-2 \cdot s_{i,j} \cdot sc_f} \cdot [s_{i,j}^2 \cdot sc_f^2])\right)^{\gamma \cdot sc_{\gamma}}\right)^r @f$
	is computed by this function and @f$ sc_b = sc_r \cdot sc_k @f$

	@f$ r @f$ is the blinding factor, @f$ sc_r @f$ is @f$ 2^{size(r) + 1} @f$, @f$ sc_k @f$ is set to @f$ 10^8 @f$ (in the configuration file) and it allows us to preserve a sufficient number of digits after the division.

	The blinding @f$ r @f$ is added by the server, before sending @f$ [d_i^*] @f$ to the client to evaluate the kernel value, @f$ [K_i^*] @f$.

	@param x the encrypted attribute vector
	@param xSquared the encrypted squared attribute vector
	@param minusTwoS scaled @f$ -2 s_i @f$
	@param encryptedSSquared @f$ [s_i^2] @f$
	@return The encrypted value of the kernel
	*/
	Paillier::Ciphertext SecureSvm::computeInverseQuadraticRbfKernelDenominator (const SecureSvm::EncryptedVector &x, const SecureSvm::EncryptedVector &xSquared, const SecureSvm::ModelVector &minusTwoS, const SecureSvm::EncryptedVector &encryptedSSquared) const {
		Paillier::Ciphertext encryptedDenominator = this->encryptedZero;

		for (size_t i = 0; i < x.size(); ++i) {
			encryptedDenominator = encryptedDenominator + xSquared[i] + x[i] * minusTwoS[i] + encryptedSSquared[i];

		}

		/// Compute [1 + c d], where c is gamma
		//multiply (d, gamma), since gamma is the unencrypted value...
		encryptedDenominator = this->encryptedScaledOne + encryptedDenominator * this->scaledGamma;

		return encryptedDenominator;
	}

}//namespace SecureRecommendations
}//namespace SeComLib