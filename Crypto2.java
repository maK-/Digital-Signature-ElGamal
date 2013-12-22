import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.math.BigInteger;
import java.util.*;
import java.io.*;
import argparser.*;
import java.lang.ArithmeticException;
/*
This tool was designed to complete Assignment2-CA547
The argument parser makes it easier to handle passed command line 
arguments.

I used the argparser library from below
http://www.cs.ubc.ca/~lloyd/java/argparser.html
*/
public class Crypto2{

    public static void main(String[] args){
        //For use with our argument parser class
        BooleanHolder gen = new BooleanHolder();
        StringHolder encr_file = new StringHolder();
        BooleanHolder ver = new BooleanHolder();

        //Parsing cmd-line arguments
        ArgParser arg = new ArgParser("./run.sh <params>\nCiaran McNally\nMake sure the files 'prime-mod-p'"+
                                        " and 'generator-g' are in your dir.");
        arg.addOption("-go %v #Run assignment and generate our values...", gen);
        arg.addOption("-f, -file %s #File to encrypt", encr_file);
        arg.addOption("-v, -verify %v #Verify correct encryption.", ver);
        arg.matchAllArgs(args);

        //This section parses the flags and various options
        if(gen.value){
            //Generate our random secret key x.
            Cryptool c = new Cryptool();
            c.gen_XY();
            c.gen_RS(encr_file.value);
        }
        else if(ver.value){
            Verify v = new Verify();
            v.erify(encr_file.value);
        }
        else{
            System.out.println("Ciaran McNally \nNo Flags or file arguments provided, use -help\n");
        }
    }
}

/*
This class simply verifies the integrity
of our results and calculations.
*/
class Verify{

    public FileWizard f = new FileWizard();
    public Cryptool c = new Cryptool();
    String hexp = f.strFromFile("prime-mod-p");
    String hexr = f.strFromFile("r.hex");
    String hexs = f.strFromFile("s.hex");
    String hexg = f.strFromFile("generator-g");
    String hexy = f.strFromFile("publickey-y.hex");
    public BigInteger p = new BigInteger(hexp,16);
    public BigInteger r = new BigInteger(hexr,16);
    public BigInteger s = new BigInteger(hexs,16);
    public BigInteger g = new BigInteger(hexg,16);
    public BigInteger y = new BigInteger(hexy,16);
 
    public void erify(String name){
        if((inBounds()) & (inScope(name))){
            System.out.println("-------------\nFile Verified!\n---------------");
            System.out.println("0<r<p  and  o<s<p-1");
            System.out.println("g^H(m)(mod P) = y^r.r^s(mod p)");
        }
        else{
            System.out.println("--------\nWARNING\n--------\nDigital Signature failed!");
        }
    }

    //Checking 0<r<p and 0<s<p-1
    public boolean inBounds(){
        BigInteger pneg1 = p.subtract(BigInteger.ONE);
        BigInteger zero = BigInteger.ZERO;

        if((r.compareTo(zero)==1)&(r.compareTo(p)==-1)&(s.compareTo(zero)==1)&(s.compareTo(pneg1)==-1)){
            return true;
        }
        else    return false;
    }
    //Checking g^H(m)(mod P) = y^r.r^s(mod p)
    public boolean inScope(String name){
        byte[] filecheck = f.fromFile(name);
        byte[] hash = c.sha256_Gen(filecheck);
        BigInteger file_hash = new BigInteger(hash);
        BigInteger first_side = g.modPow(file_hash, p);
        BigInteger t1 = y.modPow(r, p);
        BigInteger t2 = r.modPow(s, p);
        BigInteger tmp1 = t1.multiply(t2);
        BigInteger second_side = tmp1.mod(p);
        /*
        System.out.println("first\n"+first_side.toString(16));
        System.out.println("second\n"+second_side.toString(16));
        */
        if(first_side.equals(second_side)){
            return true;
        }
        else    return false;
    }
}



/*
This class is used to carry out all the cryptographic 
procedures or calculations.
*/
class Cryptool{
    //p - prime mod p
    //g - generator g
    //x - secret key x
    //y - public key y
    public BigInteger p, g, x, y;
    
    //k value
    //r - first digital signature value
    //s - second digital signature value
    public BigInteger k, r, s;

    //For use with xgcd & inverse
    public BigInteger i, j;
    public BigInteger[] arr = new BigInteger[3];

    public void gen_XY(){
        String prime_P = "";
        String gen_G = "";
        FileWizard f = new FileWizard();
        prime_P = f.strFromFile("prime-mod-p");
        gen_G = f.strFromFile("generator-g");
        p = new BigInteger(prime_P,16);
        g = new BigInteger(gen_G, 16);
        //Technique below was found in book "Java Cryptography" by Jonathan Knudsen
        int keyLen = p.bitLength() - 1; //key length is definitely less than p
        SecureRandom sec_r = new SecureRandom();
        //Private key x
        x = new BigInteger(keyLen, sec_r);
        //Public key y = g^x (mod p)
        y = g.modPow(x, p);
        System.out.println("p  =  "+p.toString(16)+"\n");
        System.out.println("g  =  "+g.toString(16)+"\n");
        System.out.println("x  =  "+x.toString(16)+"\n");
        System.out.println("y  =  "+y.toString(16)+"\n");
    }

    /*
    Generating r & s pair
    1. compute random k with 0 < k < p-1 and gcd(k, p-1) = 1
    2. Compute r as r=g^k(mod p)
    3. s = (H(m)-xr)k^-1 (mod p-1)
    4. restart above if s=0...
    */
    public void gen_RS(String encFile){
        System.out.println("Generating Signature for file... "+encFile);
        s = BigInteger.ZERO; //setting s to 0 before beginning
        BigInteger pmin1 = p.subtract(BigInteger.ONE); // p-1
        System.out.println("p-1 = "+pmin1.toString(16)+"\n");
        int keyLen = p.bitLength() - 1;
        BigInteger testing = BigInteger.ONE;
        //Hashing message/file
        FileWizard f = new FileWizard();
        byte[] fileToEnc = f.fromFile(encFile);
        byte[] hashed = sha256_Gen(fileToEnc);
        boolean isCorrect_s = false;
        
        while(!isCorrect_s){
            s = BigInteger.ZERO;
            //Step 1 - Generate k.
            BigInteger ktemp = BigInteger.ZERO;
            while(!ktemp.equals(BigInteger.ONE)){
                SecureRandom sec_r = new SecureRandom();
                k = new BigInteger(keyLen, sec_r);
                ktemp = k.gcd(pmin1);
            }
            //Step 2 r = g^k (mod p)
            r = g.modPow(k, p);
            //Step 3 H(m)
            BigInteger msg_hash = new BigInteger(hashed);
            //xr
            BigInteger xr = x.multiply(r);
            //(H(m) - xr)
            s = msg_hash.subtract(xr);
            testing = msg_hash.subtract(xr);
            //(H(m)-xr)k^-1 (mod p-1)
            //s = mod_inverse(s,pmin1);
            isCorrect_s = true;
            try{
                /*
                For testing
                s = s.multiply(k.modInverse(pmin1));
                */
                s = s.multiply(mod_inverse(k, pmin1));
                s = s.mod(pmin1);
            }
            catch(ArithmeticException e){
                isCorrect_s = false;
            }
            if((s.equals(BigInteger.ZERO))){
                isCorrect_s = false;
            }
        }
        System.out.println("k  =  "+k.toString(16)+"\n");
        System.out.println("r  =  "+r.toString(16)+"\n");
        System.out.println("s  =  "+s.toString(16)+"\n");
        System.out.println("Saving data to files...");
        f.strToFile("r.hex", r.toString(16));
        System.out.println("'r.hex' saved!");
        f.strToFile("s.hex", s.toString(16));
        System.out.println("'s.hex' saved!");
        f.strToFile("privatekey-x.hex", x.toString(16));
        System.out.println("'privatekey-x.hex' saved!");
        f.strToFile("publickey-y.hex", y.toString(16));
        System.out.println("'publickey-y' saved!");
    }


    /*
    This is the Extended Euclidean Algorithm and is used as part of
    finding the modular inverse.

    Implemented from pseudocode found here first
    http://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
    */
    public BigInteger[] xgcd (BigInteger a, BigInteger b){        
        //If conditions are met, exit!
        if(b.equals(BigInteger.ZERO)){
            arr[2] = BigInteger.ZERO;
            arr[1] = BigInteger.ONE;
            arr[0] = a;
            return arr;
        }
        //Using recursive variation of Euclidean algorithm
        arr = xgcd(b, a.mod(b));
        j = arr[2];
        i = arr[1];
        arr[1] = j;
        arr[2] = i.subtract(j.multiply(a.divide(b)));
        return arr;
    }

    /*
    This returns a modular inverse if there is one else throw exception
    */    
    public BigInteger mod_inverse(BigInteger a, BigInteger b){
        BigInteger[] tmp = xgcd(a, b);
        //multiplicative inverse not possible
        if(!tmp[0].equals(BigInteger.ONE))
            throw new ArithmeticException("Mod Inverse is not possible!");
        //is > 0
        if(tmp[1].compareTo(BigInteger.ZERO)==1)
            return tmp[1];
        else    return tmp[1].add(b);
    }

    /*
    Generate hashed byte array from file, using sha256
    */
    public byte[] sha256_Gen(byte[] input){
        try{
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest(input);
            return hash;
        }
        catch(Exception e){
            throw new RuntimeException(e);
        }
    }

    /*
    Convert byte array to hexadecimal using StringBuilder
    */
    public String byteToStr(byte[] b){
        StringBuilder hexbuffer = new StringBuilder();
        for(int i=0; i<b.length; i++){
            String hex = Integer.toHexString(0xff & b[i]);
            if(hex.length() == 1){
                hexbuffer.append(hex);
            }
        }
        return hexbuffer.toString();
    }
}


/*
This class is used to read and write byte data to and from files
*/
class FileWizard{
    
    //write byte data to a file
    public void toFile(String filename, byte[] outdata){
        try{
            File file = new File(filename);
            FileOutputStream data = new FileOutputStream(file);
            data.write(outdata);
            data.close();
        }
        catch(FileNotFoundException e){
            System.out.println("\nFile not found!");
        }
        catch(IOException e){
            System.out.println("\nIO Error!");
        }
    }    
   
    //write string data to a file
    public void strToFile(String filename, String data){
        File file = new File(filename);
        try{
            FileWriter dataf = new FileWriter(file);
            dataf.write(data);
            dataf.close();
        }
        catch(FileNotFoundException e){
            System.out.println("\nFile not found!");
        }
        catch(IOException e){
            System.out.println("\nIO Error!");
        }
    } 

    //Reads string from a file
    public String strFromFile(String filename){
        String mydata = "";
        File file = new File(filename);
        try{
            Scanner data = new Scanner(file);
            mydata = data.nextLine();
            data.close();
        }
        catch(FileNotFoundException e){
            System.out.println("\nFile not found!");
        }
        return mydata;
    }

    //Read bytes from a file.
    public byte[] fromFile(String filename){
        byte[] file_data = null;
        try{
            File file = new File(filename);
            FileInputStream data = new FileInputStream(file);
            file_data = new byte[(int)file.length()];
            data.read(file_data);
            data.close();
            return file_data;
        }
        catch(FileNotFoundException e){
            System.out.println("\nFile not found!");
        }
        catch(IOException e){
            System.out.println("\nIO Error!");
        }
        return file_data;
    }
}
