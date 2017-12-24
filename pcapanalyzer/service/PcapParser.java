package com.pcapanalyzer.service;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Observable;

import com.pcapanalyzer.bo.IPHeader;
import com.pcapanalyzer.bo.PcapDataFrame;
import com.pcapanalyzer.bo.PcapDataHeader;
import com.pcapanalyzer.bo.PcapFileHeader;
import com.pcapanalyzer.bo.PcapStruct;
import com.pcapanalyzer.bo.ProtocolData;
import com.pcapanalyzer.bo.ProtocolType;
import com.pcapanalyzer.bo.TCPHeader;
import com.pcapanalyzer.bo.TcpDataPacket;
import com.pcapanalyzer.bo.UDPHeader;
import com.pcapanalyzer.utils.DataUtils;
import com.pcapanalyzer.utils.FileUtils;
import com.pcapanalyzer.utils.LogUtils;


public class PcapParser extends Observable {

	private File pcap;     //就是你选中的pcap文件
	private String savePath;  //就是输出的位置

	private PcapStruct struct;  //就是pcap文件的结构
	private ProtocolData protocolData; //就是用来区分tcp连接的五元协议组
	private PcapDataHeader dataHeader; //数据包的头
	private IPHeader ipHeader;  //ip头
	private TCPHeader tcpHeader; //tcp头
	private UDPHeader udpHeader; //udp头
	
	private List<String[]> datas = new ArrayList<String[]>(); //这是最后分析完弹出框中的那些数据
	private List<String> filenames = new ArrayList<String>(); //这是生成所有文件的名称的集合
	
	//这个就是一个ProtocolData对应一个tcp连接从而对应
	private LinkedHashMap<ProtocolData,ArrayList<TcpDataPacket>> tcpconnections = new  LinkedHashMap<ProtocolData,ArrayList<TcpDataPacket>>();
	
	private byte[] file_header = new byte[24];
	private byte[] data_header = new byte[16];
	private byte[] content;
	private String Scontent;

	private int allpackets = 0; //包的总数量
	private int tcppackets = 0; //tcp包的数量
	private int udppackets = 0; //udp包的数量
	private int ippackets = 0;  //ip包的数量
	private int tcpnumber = 0;  //tcp连接的数量,包括80接口的不带80接口的
	

	
	private int data_offset = 0;			
	private byte[] data_content;			
	
	
	//首先通过构造方法传入文件和输出路径
	public PcapParser (File pcap, File outDir) {
		this.pcap = pcap;
		this.savePath = outDir.getAbsolutePath();
	}
	
	//然后这就是解析了,原理其实非常简单,理解了pcap文件的结构后你就可以知道每个头部所处在的位置
	public boolean parse () {
		boolean rs = true;
		struct = new PcapStruct(); //新建一个结构
		List<PcapDataHeader> dataHeaders = new ArrayList<PcapDataHeader>();//新建一个数据头的集合
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(pcap);  //开始读取
			//注意这里的file_header是一个里面什么都没有的byte数组
			int m = fis.read(file_header);  //简单来说这个read方法就是承担了运砖车的功能,把文件中的数据缓存到缓冲区,然后返回一个数,如果m<0.就代表文件读完了
			if (m > 0) {

				PcapFileHeader fileHeader = parseFileHeader(file_header); //把读取出来的文件头进行解析,然后得到一个PcapFileHeader对象
				
				if (fileHeader == null) {
					LogUtils.printObj("fileHeader", "null");
				}
				struct.setFileHeader(fileHeader);   //把文件头放入头部

				while (m > 0) {
					m = fis.read(data_header);   //既然文件头读完了,那么接下来就是数据头了,数据头有很多,所以这就是个while循环,当m<0的时候就跳出循环,此时整个文件就都读取完成了
					dataHeader = parseDataHeader(data_header);
					dataHeaders.add(dataHeader);//把解析完的数据头放入dataHeaders中
					
					//读取完这一个数据头那么怎么知道下一个数据头的位置
					//数据头中就有一个数据就是Caplen,记载了数据头的长度,然后以根据这个长度把这个数据头所在的数据包读取出来
					content = new byte[dataHeader.getCaplen()];//这个content就是这个

					m = fis.read(content);

					protocolData = new ProtocolData(); //新建一个协议五元组
					boolean isDone = parseContent();  //解析内容,其中包括ip包头和tcp包头或udp包头中的一个
					if (isDone) {
						break;         //如果读完了,跳出循环
					}
					createFiles(protocolData);  //根据协议内容创建文件
				}

				rs = true;
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			FileUtils.closeStream(fis, null);
		}

		return rs;
	}
	
	/**
	 * 解析数据包中的数据部分,也就是内容
	 *
	 */
	private boolean parseContent() throws UnsupportedEncodingException {
		// 1.读取以太网帧(没啥卵用)֡
		readPcapDataFrame(content);
		// 2. 读取IP头
		ipHeader = readIPHeader(content);
		if (ipHeader == null) {							//ip头要是空的那就读完了呗,直接回传true
			return true;
		}

		int offset = 14;							
		offset += 20;

		//3.读取tcp或是udp头
		String protocol = ipHeader.getProtocol() + ""; //在上一层的ip头中得到到底是tcp包还是udp包
		if (ProtocolType.TCP.getType().equals(protocol)) {//如果是tcp包
			protocolData.setProtocolType(ProtocolType.TCP);
			tcpHeader = readTCPHeader(content, offset);  //就调用readTCPHeader方法解析内容得到tcp头
			Scontent = new String(content,"ASCII");   //这个是我们需要每个content的String形式好后来提取http的东西
		} else if (ProtocolType.UDP.getType().equals(protocol)) {
			protocolData.setProtocolType(ProtocolType.UDP); 
			udpHeader = readUDPHeader(content, offset);//就调用readUDPHeader方法解析内容得到udp头
		} else {
			
		}

		return false;
	}
	
	
	/**
	 * 读取每个pcap文件的文件头部分
	 */
	
	public PcapFileHeader parseFileHeader(byte[] file_header) throws IOException {
		PcapFileHeader fileHeader = new PcapFileHeader();
		byte[] buff_4 = new byte[4];	
		byte[] buff_2 = new byte[2];	

		int offset = 0;
		for (int i = 0; i < 4; i ++) {
			buff_4[i] = file_header[i + offset];
		}
		offset += 4;
		int magic = DataUtils.byteArrayToInt(buff_4);
		fileHeader.setMagic(magic);

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = file_header[i + offset];
		}
		offset += 2;
		short magorVersion = DataUtils.byteArrayToShort(buff_2);
		fileHeader.setMagorVersion(magorVersion);

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = file_header[i + offset];
		}
		offset += 2;
		short minorVersion = DataUtils.byteArrayToShort(buff_2);
		fileHeader.setMinorVersion(minorVersion);

		for (int i = 0; i < 4; i ++) {
			buff_4[i] = file_header[i + offset];
		}
		offset += 4;
		int timezone = DataUtils.byteArrayToInt(buff_4);
		fileHeader.setTimezone(timezone);

		for (int i = 0; i < 4; i ++) {
			buff_4[i] = file_header[i + offset];
		}
		offset += 4;
		int sigflags = DataUtils.byteArrayToInt(buff_4);
		fileHeader.setSigflags(sigflags);

		for (int i = 0; i < 4; i ++) {
			buff_4[i] = file_header[i + offset];
		}
		offset += 4;
		int snaplen = DataUtils.byteArrayToInt(buff_4);
		fileHeader.setSnaplen(snaplen);

		for (int i = 0; i < 4; i ++) {
			buff_4[i] = file_header[i + offset];
		}
		offset += 4;
		int linktype = DataUtils.byteArrayToInt(buff_4);
		fileHeader.setLinktype(linktype);


		return fileHeader;
	}

	/**
	 * 读取pcap文件中的每个数据头部分
	 */
	public PcapDataHeader parseDataHeader(byte[] data_header){
		allpackets++;
		byte[] buff_4 = new byte[4];
		PcapDataHeader dataHeader = new PcapDataHeader();
		int offset = 0;
		for (int i = 0; i < 4; i ++) {
			buff_4[i] = data_header[i + offset];
		}
		offset += 4;
		int timeS = DataUtils.byteArrayToInt(buff_4);
		dataHeader.setTimeS(timeS);

		for (int i = 0; i < 4; i ++) {
			buff_4[i] = data_header[i + offset];
		}
		offset += 4;
		int timeMs = DataUtils.byteArrayToInt(buff_4);
		dataHeader.setTimeMs(timeMs);

		for (int i = 0; i < 4; i ++) {
			buff_4[i] = data_header[i + offset];
		}
		offset += 4;
		
		DataUtils.reverseByteArray(buff_4);
		int caplen = DataUtils.byteArrayToInt(buff_4);
		dataHeader.setCaplen(caplen);

		for (int i = 0; i < 4; i ++) {
			buff_4[i] = data_header[i + offset];
		}
		offset += 4;
		DataUtils.reverseByteArray(buff_4);
		int len = DataUtils.byteArrayToInt(buff_4);
		dataHeader.setLen(len);


		return dataHeader;
	}

	/**
	 * 读取以太网帧,没啥卵用֡
	 * 
	 */
	public void readPcapDataFrame(byte[] content) {
		PcapDataFrame dataFrame = new PcapDataFrame();
		int offset = 12;
		byte[] buff_2 = new byte[2];
		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
		}
		short frameType = DataUtils.byteArrayToShort(buff_2);
		dataFrame.setFrameType(frameType);
		
	}
	
	
	//读取IP头
	private IPHeader readIPHeader(byte[] content) {
		ippackets++;
		int offset = 14;
		IPHeader ip = new IPHeader();

		byte[] buff_2 = new byte[2];
		byte[] buff_4 = new byte[4];

		byte varHLen = content[offset ++];				// offset = 15
		if (varHLen == 0) {
			return null;
		}
		
		ip.setVarHLen(varHLen);

		byte tos = content[offset ++];					// offset = 16
		ip.setTos(tos);

		for (int i = 0; i < 2; i ++) {		
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 18
		short totalLen = DataUtils.byteArrayToShort(buff_2);
		ip.setTotalLen(totalLen);

		for (int i = 0; i < 2; i ++) {			
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 20
		short id = DataUtils.byteArrayToShort(buff_2);
		ip.setId(id);

		for (int i = 0; i < 2; i ++) {					
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 22
		short flagSegment = DataUtils.byteArrayToShort(buff_2);
		ip.setFlagSegment(flagSegment);

		byte ttl = content[offset ++];					// offset = 23
		ip.setTtl(ttl);

		byte protocol = content[offset ++];				// offset = 24
		ip.setProtocol(protocol);

		for (int i = 0; i < 2; i ++) {					
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 26
		short checkSum = DataUtils.byteArrayToShort(buff_2);
		ip.setCheckSum(checkSum);

		for (int i = 0; i < 4; i ++) {					
			buff_4[i] = content[i + offset];
		}
		offset += 4;									// offset = 30
		int srcIP = DataUtils.byteArrayToInt(buff_4);
		ip.setSrcIP(srcIP);

		StringBuilder builder = new StringBuilder();
		for (int i = 0; i < 4; i++) {
			builder.append((int) (buff_4[i] & 0xff));
			builder.append(".");
		}
		builder.deleteCharAt(builder.length() - 1);
		String sourceIP = builder.toString();
		protocolData.setSrcIP(sourceIP);

		for (int i = 0; i < 4; i ++) {		
			buff_4[i] = content[i + offset];
		}
		offset += 4;									// offset = 34
		int dstIP = DataUtils.byteArrayToInt(buff_4);
		ip.setDstIP(dstIP);

		builder = new StringBuilder();
		for (int i = 0; i < 4; i++) {
			builder.append((int) (buff_4[i] & 0xff));
			builder.append(".");
		}
		builder.deleteCharAt(builder.length() - 1);
		String destinationIP = builder.toString();
		protocolData.setDesIP(destinationIP);


		return ip;
	}

	
	//读取TCP头
	private TCPHeader readTCPHeader(byte[] content2, int offset) {
		byte[] buff_2 = new byte[2];
		byte[] buff_4 = new byte[4];
		tcppackets++;
		TCPHeader tcp = new TCPHeader();

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 36
		short srcPort = DataUtils.byteArrayToShort(buff_2);
		tcp.setSrcPort(srcPort);

		String sourcePort = validateData(srcPort);
		protocolData.setSrcPort(sourcePort);

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 38
		short dstPort = DataUtils.byteArrayToShort(buff_2);
		tcp.setDstPort(dstPort);

		String desPort = validateData(dstPort);
		protocolData.setDesPort(desPort);

		for (int i = 0; i < 4; i ++) {
			buff_4[i] = content[i + offset];
		}
		offset += 4;									// offset = 42
		int seqNum = DataUtils.byteArrayToInt(buff_4);
		tcp.setSeqNum(seqNum);

		for (int i = 0; i < 4; i ++) {
			buff_4[i] = content[i + offset];
		}
		offset += 4;									// offset = 46
		int ackNum = DataUtils.byteArrayToInt(buff_4);
		tcp.setAckNum(ackNum);

		byte headerLen = content[offset ++];			// offset = 47
		tcp.setHeaderLen(headerLen);

		byte flags = content[offset ++];				// offset = 48
		tcp.setFlags(flags);

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 50
		short window = DataUtils.byteArrayToShort(buff_2);
		tcp.setWindow(window);

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 52
		short checkSum = DataUtils.byteArrayToShort(buff_2);
		tcp.setCheckSum(checkSum);

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 54
		short urgentPointer = DataUtils.byteArrayToShort(buff_2);
		tcp.setUrgentPointer(urgentPointer);

		data_offset = offset;

		return tcp;
	}

	
	//读取UDP头
	private UDPHeader readUDPHeader(byte[] content, int offset) {
		byte[] buff_2 = new byte[2];
		udppackets++;
		UDPHeader udp = new UDPHeader();
		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 36
		short srcPort = DataUtils.byteArrayToShort(buff_2);
		udp.setSrcPort(srcPort);

		String sourcePort = validateData(srcPort);
		protocolData.setSrcPort(sourcePort);

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 38
		short dstPort = DataUtils.byteArrayToShort(buff_2);
		udp.setDstPort(dstPort);

		String desPort = validateData(dstPort);
		protocolData.setDesPort(desPort);

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 40
		short length = DataUtils.byteArrayToShort(buff_2);
		udp.setLength(length);

		for (int i = 0; i < 2; i ++) {
			buff_2[i] = content[i + offset];
		}
		offset += 2;									// offset = 42
		short checkSum = DataUtils.byteArrayToShort(buff_2);
		udp.setCheckSum(checkSum);
		
		data_offset = offset;

		return udp;
	}

	//创建文件
	public void createFiles(ProtocolData protocolData) {
		String protocol = "TCP";  //默认是TCP的前缀
		String suffix = ".pcap";  //默认是.pcap的文件格式
		if (protocolData.getProtocolType() == ProtocolType.UDP) { //看看是哪个协议的包
			protocol = "UDP";
		}  else if (protocolData.getProtocolType() == ProtocolType.OTHER) {
			return;
		}
		//创建文件名,由于tcp连接是双向的,也就是说(IP1, Port1)→(IP2, Port2) and (IP2, Port2)→(IP1, Port1)是同一个连接
		String filename = protocol + "[" + protocolData.getSrcIP() + "]"
								   + "[" + protocolData.getSrcPort() + "]"
								   + "[" + protocolData.getDesIP() + "]"
								   + "[" + protocolData.getDesPort() + "]";
		
		String reverseFilename = protocol + "[" + protocolData.getDesIP() + "]"
								   		  + "[" + protocolData.getDesPort() + "]"
								   		  + "[" + protocolData.getSrcIP() + "]"
								   		  + "[" + protocolData.getSrcPort() + "]";
		boolean append = false;
		//就是检验是否有相同的tcp连接
		if (filenames.contains(filename)) {
			if(protocol == "TCP") {
				if(protocolData.getSrcPort().equals("80")||protocolData.getDesPort().equals("80")) {  //如果协议是tcp而且源端口或者目标端口是80,我们就把这个包带上
					TcpDataPacket tcpdatapacket = new TcpDataPacket(ipHeader,tcpHeader,dataHeader,Scontent);
					tcpconnections.get(protocolData).add(tcpdatapacket);
				}
			}
			append = true;

		} else {
			append = false;
						
			if (filenames.contains(reverseFilename)) {
				if(protocol == "TCP") {
					if(protocolData.getSrcPort().equals("80")||protocolData.getDesPort().equals("80")) { //如果协议是tcp而且源端口或者目标端口是80,我们就把这个包带上
						TcpDataPacket tcpdatapacket = new TcpDataPacket(ipHeader,tcpHeader,dataHeader,Scontent);
						tcpconnections.get(protocolData).add(tcpdatapacket);
					}
				}
				append = true;
				filename = reverseFilename;
			} else {
				filenames.add(filename);
				if(protocol == "TCP") {
					tcpnumber++;
					if(protocolData.getSrcPort().equals("80")||protocolData.getDesPort().equals("80")) { //如果协议是tcp而且源端口或者目标端口是80,我们就把这个包带上
						tcpconnections.put(protocolData, new ArrayList());
						TcpDataPacket tcpdatapacket = new TcpDataPacket(ipHeader,tcpHeader,dataHeader,Scontent);
						tcpconnections.get(protocolData).add(tcpdatapacket);
					}
				}
			}
			
		}
		
		filename = DataUtils.validateFilename(filename);
		String pathname = savePath + "\\" + protocol + "\\" + filename + suffix;
		
		int data_size = content.length - data_offset;
		data_content = new byte[data_size];
		for (int i = 0; i < data_size; i ++) {
			data_content[i] = content[i + data_offset];
		}
		String pathname_data = savePath + "\\" + protocol + "\\data\\" + filename + ".txt";
		
		try {
			File file = new File(pathname);
			FileOutputStream fos = new FileOutputStream(file, append);
			
			File data_file = new File(pathname_data);
			FileOutputStream fos_data = new FileOutputStream(data_file, append);
			
			if (!append) {
				fos.write(file_header);
				
				String[] data = new String[2];
				data[0] = filename;
				data[1] = pathname;
				datas.add(data);
				super.setChanged();								
				super.notifyObservers(datas);					
				
				String logPath = savePath + "\\" + protocol + "\\" + protocol + ".txt";
				FileUtils.writeLineToFile(filename, new File(logPath), true);
			}
			fos.write(data_header);
			fos.write(content);
			
			fos_data.write(data_content);
			
			FileUtils.closeStream(null, fos);
			FileUtils.closeStream(null, fos_data);
			
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} 
		
	}

	private String validateData (int data) {
		String rs = data + "";
		if (data < 0) {
			String binaryPort = Integer.toBinaryString(data);
			rs = DataUtils.binaryToDecimal(binaryPort) + "";
		}

		return rs;
	}
	public Integer getallpcaket() {
		return allpackets;
	}
	public Integer gettcppacket() {
		return tcppackets;
	}
	public Integer getudppacket() {
		return udppackets;
	}
	public Integer getippackets() {
		return ippackets;
	}
	public Integer gettcpconnection() {
		return tcpnumber;
	}
	public LinkedHashMap<ProtocolData,ArrayList<TcpDataPacket>> gettcpconnections(){
		return tcpconnections;
	}
	
}
