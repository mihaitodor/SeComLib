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

    struct Row
    {
        public string m_data;
        public string m_gamma;
        public string m_c;
        public double m_auc;
        public double m_accuracy;
        public double m_avgNumSVs;

        public Row(string data, string gamma, string c, double auc, double accuracy, double avgNumSVs)
        {
            m_data = data;
            m_gamma = gamma;
            m_c = c;
            m_auc = auc;
            m_accuracy = accuracy;
            m_avgNumSVs = avgNumSVs;
        }
    }

    class File
    {
        public string m_fileName;
        public double m_maxAccuracy = double.MinValue;
        public List<Row> m_rows = new List<Row>();

        public File(string name)
        {
            m_fileName = name;
        }
    }

    /*
    class Format 
    {
        public double Accuracy;
        public double Precesion;
        public double Recall;
        public string FileName;

        public Format(string[] input)
        {
            Accuracy = Double.Parse(input[0]);
            Precesion = Double.Parse(input[1]);
            Recall = Double.Parse(input[2]);
            FileName = input[7];
        }
    }
     */

    class Program
    {
        static string resultsDirectory;

        /*
        static void ProcessFiles(string path)
        {
            string[] lines = IO.File.ReadAllLines(path);
            List<string> linesList = new List<string>();

            for (int i = 7; i < lines.Length - 8; i++)
            {
                linesList.Add(lines[i]);
            }

            List<Format> elements = new List<Format>();

            linesList.ForEach(l => {
                elements.Add(new Format(l.Split('|')));
            });

            var groups = elements.GroupBy(e => {
                return e.FileName; 
            });


            groups.ToList().ForEach(g => {
                double max = g.ToList().Max(e => {
                    return e.Accuracy; 
                });


            });

        }
         * */

        static void Main(string[] args)
        {
            if (args.Length != 0 && args[0] != "")
            {
                resultsDirectory = args[0] + "\\";
            }
            else
            {
                //resultsDirectory = Directory.GetCurrentDirectory() + "\\";
                resultsDirectory = "D:\\mtodor\\Desktop\\training_test\\results_02.11.2012\\";
            }

            Console.WriteLine("Selecting entry with (almost) maximum Accuracy and minimum AvgNumSVs for each file.");

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

                List<File> files = new List<File>();
                //determine max accuracy for every file
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

                                string fileName = groups[8].Value;
                                //Output format: Accuracy|AUC|AvgNumSVs|file|Gamma|C
                                string data = groups[1].Value + '|' + groups[6].Value + '|' + groups[7].Value + '|' + groups[8].Value + '|' + groups[9].Value + '|' + groups[10].Value;
                                double auc;
                                double accuracy;
                                double avgNumSVs;
                                double.TryParse(groups[6].Value, out auc);//AUC
                                double.TryParse(groups[1].Value, out accuracy);//Accuracy
                                double.TryParse(groups[7].Value, out avgNumSVs);//AvgNumSVs

                                if (files.Count > 0 && files.Last().m_fileName == fileName)
                                {
                                    files.Last().m_rows.Add(new Row(data, groups[9].Value, groups[10].Value, auc, accuracy, avgNumSVs));

                                    if (accuracy > files.Last().m_maxAccuracy)
                                    {
                                        files.Last().m_maxAccuracy = accuracy;
                                    }
                                }
                                else
                                {
                                    files.Add(new File(fileName));
                                    files.Last().m_rows.Add(new Row(data, groups[9].Value, groups[10].Value, auc, accuracy, avgNumSVs));
                                }
                            }
                        }
                    }
                }

                double accuracyTolerance = 2.0;

                List<File> goodAccuracies = new List<File>();
                foreach (File file in files)
                {
                    goodAccuracies.Add(new File(file.m_fileName));
                    goodAccuracies.Last().m_maxAccuracy = file.m_maxAccuracy;
                    foreach (Row row in file.m_rows)
                    {
                        if (row.m_accuracy + accuracyTolerance > file.m_maxAccuracy)
                        {
                            goodAccuracies.Last().m_rows.Add(row);
                        }
                    }
                }

                //compute minimum avgNumSVs
                foreach (File goodAccuracy in goodAccuracies)
                {
                    Row minAvgNumSV = goodAccuracy.m_rows.Last(minimum => minimum.m_avgNumSVs == goodAccuracy.m_rows.Min(row => row.m_avgNumSVs));

                    output.Add(new Optimum(goodAccuracy.m_fileName, minAvgNumSV.m_gamma, minAvgNumSV.m_c));
                    Console.WriteLine(minAvgNumSV.m_data);
                }

                string test = "1";
                
            }

            Console.WriteLine();
            return output;
        }
    }
}
