/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package rc5_swing;

import java.util.Random;

/**
 *
 * @author admin
 */
public class RC5Cipher
    {
        private int W = 64; //long type has 64 bits                                                                  
        private int R = 12; //rounds count            
        //magic constants
        private final long PW64 = 0xB7E151628AED2A6BL;      
        private final long QW64 = 0x9E3779B97F4A7C15L; 
        private final long PW32 = 0xB7E15162L;   
        private final long QW32 = 0x9E3779B9L;     
        private final long PW16 = 0xB7E1L;        
        private final long QW16 = 0x9E37L;  
        private long[] L, S;//arrays for key and extended table
        private int t,b,u,c;
        public RC5Cipher(){
            
        }
        public RC5Cipher(byte[] key, int r)
        {
            R=r;
            b = key.length;//reading key length
            t = 2 * (R + 1); //size of extended table
            u = W >> 3;//получаем количество байт в слове побитовым сдвигом
            if(b%u==0)
                c=b/u;
            else
                c=b/u+1;
            
            L = new long[c];//массив слов из ключа
            S = new long[t];//расширенная таблица
            int i,j;
            for (i = b - 1; i >= 0; i--)//идем в обратную сторону (записываем с правого края массива)
            {
                L[i/u] = Long.rotateLeft(L[i / u], 8) + key[i];
            }
            S[0] = PW64;
            for (i = 1; i < t; i++)//initialize extended table
            {
                S[i] = S[i - 1] + QW64;
            }
            long g=0; long h=0;
            i = j = 0;
            int n = 3 * Math.max(t, c);
            for (int k = 0; k < n; k++)
            {
                g = S[i] = Long.rotateLeft((S[i] + g + h), 3);
                h = L[j] = Long.rotateRight((L[j] + g + h), (int)(g + h));
                i = (i + 1) % t; j = (j + 1) % c;
            }
        }
        public long toLong( final byte[] b)//convert byte array to long (64 bits = 8 bytes)
        {
            long res = 0;
            for (int i = 0; i < 8; i++) {
            res = res<<8;
            res = res|(b[i] & 0xFF);
            }
            return res;
        }

        public byte[] toBytes(long l)//convert long to 8 bytes
        {
            byte[] result = new byte[8];
            for (int i = 7; i >= 0; i--) {
                result[i] = (byte)(l & 0xFF);
                l=l>>8;
            }
            return result;
        }

        public byte[] Cipher(byte[] original, byte[] res)
        {
            byte[]aarr = new byte[8];
            byte[]barr = new byte[8];
            for(int i=0;i<8;i++){
                aarr[i] = original[i];
                barr[i] = original[8+i];
            }
            
            long a = toLong(aarr)+S[0];
            long b = toLong(barr)+S[1];
            
            for (int i = 1; i < R + 1; i++)
            {
                a = Long.rotateLeft((a ^ b), (int)b) ^ S[2 * i];
                b = Long.rotateLeft((b ^ a), (int)a) ^ S[2 * i + 1];
            }

            aarr=toBytes(a);
            barr=toBytes(b);
            for(int i=0;i<8;i++){
                res[i] = aarr[i];
                res[i+8] = barr[i];
            }
            return res;
        }

        public byte[] Decipher(byte[] block, byte[] res)
        {
            byte[]aarr = new byte[8];
            byte[]barr = new byte[8];
            for(int i=0;i<8;i++){
                aarr[i] = block[i];
                barr[i] = block[8+i];
            }
            
            long a = toLong(aarr);
            long b = toLong(barr);
            
            for (int i = R; i > 0; i--)
            {
                b = Long.rotateRight((b ^ S[2 * i + 1]), (int)a) ^ a;
                a = Long.rotateRight((a ^ S[2 * i]), (int)b) ^ b;
            }
            b = b - S[1];
            a = a - S[0];
            aarr=toBytes(a);
            barr=toBytes(b);
            for(int i=0;i<8;i++){
                res[i] = aarr[i];
                res[i+8] = barr[i];
            }
            return res;
        }
     
}
