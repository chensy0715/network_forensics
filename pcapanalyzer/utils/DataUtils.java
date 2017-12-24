package com.pcapanalyzer.utils;

import java.math.BigDecimal;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.List;


public class DataUtils {

	private DataUtils () {}


	public static String formatHexData (String hex, int type) {
		int len = hex.length();		

		if (type == 0) {			
			if (len < 4) {			
				int correct = 4 - len;
				for (int i = 0; i < correct; i ++) {
					hex = "0" + hex;
				}
			}
		} else if (type == 1) {		
			if (len <= 4) {			
				int correct = 4 - len;
				for (int i = 0; i < correct; i ++) {
					hex = "0" + hex;// ǰ�˲� 0
				}

				hex += " 0000";		
			} else if (len > 4) {	
				List<String> datas = new ArrayList<String>();
				for (String s : hex.split("")) {
					datas.add(s);
				}

				int correct = 9 - len;
				for (int i = 0; i < correct; i ++) {
					datas.add(" ");
				}
				for (int i = len; i > 3; i --) {
					datas.set(i, datas.get(i - 1));
				}
				datas.set(4, " ");
				StringBuilder builder = new StringBuilder();
				for (String s : datas) {
					builder.append(s);
				}
				hex = builder.toString();

				if (hex.length() < 9) {
					for (int i = 0; i < correct - 1; i ++) {
						hex += "0";
					}
				}
			}
		} else {					
			return null;
		}


		return null;
	}

	public static void reverseByteArray(byte[] arr){
		byte temp;
		int n = arr.length;
		for(int i = 0; i < n / 2; i++){
			temp = arr[i];
			arr[i] = arr[n - 1 - i];
			arr[n - 1 - i] = temp;
		}
	}

	public static int byteToInt (byte b) {
		return (b & 0xff);
	}

	public static int byteArrayToInt(byte[] b){
		return byteArrayToInt(b, 0);
	}

	public static int byteArrayToInt(byte[] bytes, int offset){
		int value= 0;
		for (int i = 0; i < 4; i++) {
			int shift= (4 - 1 - i) * 8;
			value +=(bytes[i] & 0x000000FF) << shift;//����λ��
		}

		return value;
	}

	public static short byteArrayToShort(byte[] b){
		return byteArrayToShort(b, 0);
	}

	public static short byteArrayToShort(byte[] b,int offset){
		return (short) (((b[offset] & 0xff) << 8) | (b[offset + 1] & 0xff)); 
	}

	public static String byteToHexString (byte b) {
		return intToHexString(byteToInt(b));
	}

	public static byte[] intToByteArray(int i) {
		byte[] result = new byte[4];   
		result[0] = (byte)((i >> 24) & 0xFF);
		result[1] = (byte)((i >> 16) & 0xFF);
		result[2] = (byte)((i >> 8) & 0xFF); 
		result[3] = (byte)(i & 0xFF);
		return result;
	}

	public static String shortToHexString (short s) {
		String hex = intToHexString(s);
		int len = hex.length();
		if (len > 4) {
			hex = hex.substring(4);
		} 

		len = hex.length();
		if (len < 4) {	
			int n = 4 - len;
			for (int i = 0; i < n; i ++) {
				hex = "0" + hex;
			}
		}

		return "0x" + hex;
	}

	public static String intToHexString (int data) {
		return Integer.toHexString(data);
	}

	public static int binaryToDecimal (String str) {
		String[] strs = str.split("");
		List<Integer> datas = new ArrayList<Integer>();
		for (String s : strs) {
			datas.add(Integer.valueOf(s));
		}
		int size = datas.size();

		int values = 0;
		if (size <= 16) {
			for (int i = 0; i < size; i ++) {
				values += (datas.get(i) * ((int) Math.pow(2, size - i - 1)));
			}
		} else {	
			int offset = size - 16;
			for (int i = 0; i < 16; i ++) {
				values += (datas.get(i + offset) * ((int) Math.pow(2, 16 - i - 1)));
			}
		}

		return values;
	}

	public static String byteArrayToBinaryString (byte[] bytes) {
		String line = "";
		for (byte b : bytes) {
			line += (Integer.toBinaryString(byteToInt(b)));
		}

		return line;
	}

	public static String toMBString (long i) {
		DecimalFormat format = new DecimalFormat("#.##");	
		return format.format((i / 1024.0));
	}

	public static BigDecimal toMB (long i) {
		return roundDown(i / 1024.0);
	}

	public static BigDecimal roundDown (double d) {
		BigDecimal decimal = new BigDecimal((d));
		return scale(decimal, 2);
	}

	public static BigDecimal scale (BigDecimal decimal, int scale) {
		return decimal.setScale(scale, BigDecimal.ROUND_DOWN);
	}

	public static String validateFilename (String filename) {
		
		String[] s1 = filename.split("\\[");	// TCP  59.175.132.20] 	80]   192.168.1.40]	1581]	
		String protocol = s1[0];
		String ip1 = s1[1].split("\\]")[0];
		String port1 = s1[2].split("\\]")[0];
		String ip2 = s1[3].split("\\]")[0];
		String port2 = s1[4].split("\\]")[0];

		String[] ip_s1 = ip1.split("\\.");
		String[] ip_s2 = ip2.split("\\.");

		String rs = protocol + "[" + ip1 + "]"
				 			 + "[" + port1 + "]"
				 			 + "[" + ip2 + "]"
				 			 + "[" + port2 + "]";
		String tmp_ip = ip1;
		String tmp_port = port1;
		
		int ip1_part1 = Integer.valueOf(ip_s1[0]);
		int ip2_part1 = Integer.valueOf(ip_s2[0]);
		
		if (ip1_part1 > ip2_part1) {			
			rs = swape(protocol, ip2, port2, tmp_ip, tmp_port);
		}  else if (ip1_part1 == ip2_part1) {	
			
			int ip1_part2 = Integer.valueOf(ip_s1[1]);
			int ip2_part2 = Integer.valueOf(ip_s2[1]);
			if (ip1_part2 > ip2_part2) {
				rs = swape(protocol, ip2, port2, tmp_ip, tmp_port);
			} else if (ip1_part2 == ip2_part2) {	
				
				int ip1_part3 = Integer.valueOf(ip_s1[2]);
				int ip2_part3 = Integer.valueOf(ip_s2[2]);
				if (ip1_part3 > ip2_part3) {
					rs = swape(protocol, ip2, port2, tmp_ip, tmp_port);
				} else if (ip1_part3 == ip2_part3) {	
					
					int ip1_part4 = Integer.valueOf(ip_s1[3]);
					int ip2_part4 = Integer.valueOf(ip_s2[3]);
					if (ip1_part4 > ip2_part4) {
						rs = swape(protocol, ip2, port2, tmp_ip, tmp_port);
					} 
				}
			}
		} 
		
		return rs;
	}
	
	private static String swape (String protocol, String ip2, String port2, String tmp_ip, String tmp_port) {
		String ip1 = ip2;
		ip2 = tmp_ip;

		String port1 = port2;
		port2 = tmp_port;
		String rs = protocol + "[" + ip1 + "]"
							 + "[" + port1 + "]"
							 + "[" + ip2 + "]"
							 + "[" + port2 + "]";
		
		return rs;
	}

}