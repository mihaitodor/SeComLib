using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Text.RegularExpressions;
using System.Collections;

namespace parse_results
{
    struct Optimum
    {
        public string m_name;
        public string m_gamma;
        public string m_c;
        
        public Optimum(string name, string gamma, string c)
        {
            m_name = name;
            m_gamma = gamma;
            m_c = c;
        }
    }

    class Program
    {
        static string resultsDirectory;

        static void Main(string[] args)
        {
            if (args.Length != 0 && args[0] != "")
            {
                resultsDirectory = args[0] + "\\";
            }
            else
            {
                //resultsDirectory = Directory.GetCurrentDirectory() + "\\";
                resultsDirectory = "D:\\mtodor\\Desktop\\training_test\\results_partial_01.11.2012\\";
            }

            //Console.WriteLine("Selecting entry with maximum AUC for each file.");
            Console.WriteLine("Selecting entry with maximum Accuracy for each file.");
            //Console.WriteLine("Selecting entry with maximum AvgNumSVs for each file.");

            Console.WriteLine();
            Console.WriteLine("Output format: Accuracy|AUC|AvgNumSVs|file|Gamma|C");
            Console.WriteLine();
            Console.WriteLine();

            try
            {
                ArrayList relevanceLinear = ComputeMaximums("medical_relevance_linear.txt");
                ArrayList relevanceHomogeneousPoly = ComputeMaximums("medical_relevance_homogeneous_poly.txt");
                ArrayList relevanceInhomogeneousPoly = ComputeMaximums("medical_relevance_inhomogeneous_poly.txt");
                ArrayList relevanceRbf = ComputeMaximums("medical_relevance_rbf.txt");

                ArrayList safetyLinear = ComputeMaximums("safety_linear.txt");
                ArrayList safetyHomogeneousPoly = ComputeMaximums("safety_homogeneous_poly.txt");
                ArrayList safetyInhomogeneousPoly = ComputeMaximums("safety_inhomogeneous_poly.txt");
                ArrayList safetyRbf = ComputeMaximums("safety_rbf.txt");

                Console.WriteLine("Medical relevance:");
                for (int i = 0; i < relevanceLinear.Count; ++i)
                {
                    Console.WriteLine("set CLinear={0}", ((Optimum)relevanceLinear[i]).m_c);
                    Console.WriteLine("set CHomogeneousPoly={0}", ((Optimum)relevanceHomogeneousPoly[i]).m_c);
                    Console.WriteLine("set GammaInhomogeneousPoly={0}", ((Optimum)relevanceInhomogeneousPoly[i]).m_gamma);
                    Console.WriteLine("set CInhomogeneousPoly={0}", ((Optimum)relevanceInhomogeneousPoly[i]).m_c);
                    Console.WriteLine("set GammaRbf={0}", ((Optimum)relevanceRbf[i]).m_gamma);
                    Console.WriteLine("set CRbf={0}", ((Optimum)relevanceRbf[i]).m_c);
                    Console.WriteLine("set WeightOne=1");
                    Console.WriteLine("set WeightMinusOne=1");
                    Console.WriteLine("call:train_svms {0}, medical_relevance, !CLinear!, !CHomogeneousPoly!, !GammaInhomogeneousPoly!, !CInhomogeneousPoly!, !GammaRbf!, !CRbf!, !WeightOne!, !WeightMinusOne!", ((Optimum)relevanceLinear[i]).m_name.Substring(0, ((Optimum)relevanceLinear[i]).m_name.IndexOf('.')));
                    Console.WriteLine();
                }
                
                Console.WriteLine("Safety:");
                for (int i = 0; i < safetyLinear.Count; ++i)
                {
                    Console.WriteLine("set CLinear={0}", ((Optimum)safetyLinear[i]).m_c);
                    Console.WriteLine("set CHomogeneousPoly={0}", ((Optimum)safetyHomogeneousPoly[i]).m_c);
                    Console.WriteLine("set GammaInhomogeneousPoly={0}", ((Optimum)safetyInhomogeneousPoly[i]).m_gamma);
                    Console.WriteLine("set CInhomogeneousPoly={0}", ((Optimum)safetyInhomogeneousPoly[i]).m_c);
                    Console.WriteLine("set GammaRbf={0}", ((Optimum)safetyRbf[i]).m_gamma);
                    Console.WriteLine("set CRbf={0}", ((Optimum)safetyRbf[i]).m_c);
                    Console.WriteLine("set WeightOne=1");
                    Console.WriteLine("set WeightMinusOne=1");
                    Console.WriteLine("call:train_svms {0}, safety, !CLinear!, !CHomogeneousPoly!, !GammaInhomogeneousPoly!, !CInhomogeneousPoly!, !GammaRbf!, !CRbf!, !WeightOne!, !WeightMinusOne!", ((Optimum)safetyLinear[i]).m_name.Substring(0, ((Optimum)safetyLinear[i]).m_name.IndexOf('.')));
                    Console.WriteLine();
                }
                
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }

        static ArrayList ComputeMaximums(string inputFile)
        {
            Console.WriteLine("Processing: {0}", inputFile);

            ArrayList output = new ArrayList();

            string pattern = @"(.*)\|(.*)\|(.*)\|(.*)\|(.*)\|(.*)\|(.*)\|(.*)\|(.*)\|(.*)";
            Regex rgx = new Regex(pattern, RegexOptions.IgnoreCase);

            using (StreamReader sr = new StreamReader((new Uri(resultsDirectory + inputFile).AbsolutePath)))
            {
                String line;
                string fileName = "";
                string gamma = "";
                string c = "";
                string accuracyString = "";
                string aucString = "";
                string avgNumSVsString = "";
                //double auc = double.MinValue;//AUC
                double accuracy = double.MinValue;//Accuracy
                //double avgNumSVs = double.MaxValue;

                while ((line = sr.ReadLine()) != null)
                {
                    if ("" != line)
                    {
                        if (line[0] == '0' || line[0] == '1' || line[0] == '2' || line[0] == '3' || line[0] == '4' || line[0] == '5' || line[0] == '6' || line[0] == '7' || line[0] == '8' || line[0] == '9')
                        {
                            MatchCollection matches = rgx.Matches(line);
                            if (matches.Count > 0)
                            {
                                GroupCollection groups = matches[0].Groups;

                                if (fileName == groups[8].Value)
                                {
                                    double contender;
                                    //double.TryParse(groups[6].Value, out contender);//AUC
                                    double.TryParse(groups[1].Value, out contender);//Accuracy
                                    //double.TryParse(groups[7].Value, out contender);//AvgNumSVs

                                    //if (contender >= auc)//AUC
                                    if (contender >= accuracy)//Accuracy
                                    //if (contender <= avgNumSVs)//AvgNumSVs
                                    {
                                        //auc = contender;//AUC
                                        accuracy = contender;//Accuracy
                                        //avgNumSVs = contender;//AvgNumSVs
                                        accuracyString = groups[1].Value;
                                        aucString = groups[6].Value;
                                        avgNumSVsString = groups[7].Value;
                                        gamma = groups[9].Value;
                                        c = groups[10].Value;
                                    }
                                }
                                //new file
                                else
                                {
                                    if ("" != fileName)
                                    {
                                        output.Add(new Optimum(fileName, gamma, c));
                                        Console.WriteLine("{0}|{1}|{2}|{3}|{4}|{5}", accuracyString, aucString, avgNumSVsString, fileName, gamma, c);
                                    }
                                    fileName = groups[8].Value;
                                    //double.TryParse(groups[6].Value, out auc);//AUC
                                    double.TryParse(groups[1].Value, out accuracy);//Accuracy
                                    //double.TryParse(groups[7].Value, out avgNumSVs);//AvgNumSVs
                                    accuracyString = groups[1].Value;
                                    aucString = groups[6].Value;
                                    avgNumSVsString = groups[7].Value;
                                    gamma = groups[9].Value;
                                    c = groups[10].Value;
                                }
                            }
                        }
                    }
                }

                output.Add(new Optimum(fileName, gamma, c));
                //write last maximum
                Console.WriteLine("{0}|{1}|{2}|{3}|{4}|{5}", accuracyString, aucString, avgNumSVsString, fileName, gamma, c);
            }

            Console.WriteLine();
            return output;
        }
    }
}
