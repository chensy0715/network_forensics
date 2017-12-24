package com.pcapanalyzer.ui;

import java.awt.BorderLayout;
import java.awt.EventQueue;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Observable;
import java.util.Observer;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;

import com.pcapanalyzer.bo.PcapDataHeader;
import com.pcapanalyzer.bo.ProtocolData;
import com.pcapanalyzer.bo.TcpDataPacket;
import com.pcapanalyzer.observer.PcapParserObserver;
import com.pcapanalyzer.service.PcapParser;
import com.pcapanalyzer.utils.Constant;
import com.pcapanalyzer.utils.DataUtils;
import com.pcapanalyzer.utils.FileUtils;
import com.pcapanalyzer.utils.LogUtils;
import com.pcapanalyzer.utils.PropertiesUtils;
import com.pcapanalyzer.utils.WindowUtils;

public class MainFrame extends BaseFrame implements ActionListener, Observer {

	private static final long serialVersionUID = 1L;
	private static final int FRAME_WIDTH = 500;			 //界面宽度
	private static final int FRAME_HEIGHT = 200;         //界面高度
	private static final int RECENT_MAX_NUM = 5;         //最多显示的历史文件的数量
	
	private static final String COMMAND_IN = "choose pcap";       //
	private static final String COMMAND_OUT = "choose output file";
	private static final String COMMAND_START = "start pcapAnalyzer";
	
	private static final String COMMAND_OPEN = "  | Open Pcap";
	private static final String COMMAND_EXIT = "  | Exit";
	private static final String COMMAND_ABOUT = "  | About";
	private static final String COMMAND_OPEN_RECENT = "  | Reopen Closed File";
	private static final String COMMAND_CLEAR_ITEM = "  | Clear Items";
	
	private File pcap_file;			//这是你要解析的pcap文件						
	private File out_dir;			//这是你要输出的目录						

	private JPanel panel;           //面板
	
	private JTextField jtf_in;      //文本输入框,就是第一个选择pcap文件那个     
	private JTextField jtf_out;     //文本输入框,就是第二个选择输出文件位置那个
	
	private JButton jbtn_in;        //就是第一个按钮,选择pcap文件
	private JButton jbtn_out;       //就是第二个按钮,选择输出文件位置的按钮
	private JButton jbtn_analysis;  //就是最下面分析的按钮 
	
	private JFileChooser chooser;   //文件选择器,你点按钮就会弹出这个让你选择文件
	 
	private JMenu mFOpenRecent;      //就是那个最近打开文件的那个菜单
	private List<JMenuItem> mItemRecents; //就是放置你最近打开的历史文件的菜单项的List
	private JMenuItem mItemFORClear;  //菜单项	
	private JMenuItem mItemFOpen;	  //菜单项
	private JMenuItem mItemFExit;     //菜单项
	private JMenuItem mItemHAbout;    //菜单项
	
	public MainFrame() {
		super.setTitle("PcapAnalyzer");  //这是设置窗口名称
		initViews();  //初始化面板和菜单
		initEvents(); //初始化各种监听事件
	}
	
 
	public static void start () {
		new MainFrame().setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
	}
	

	public void initEvents() {
		//给按钮和菜单项设置监听事件
		jbtn_in.addActionListener(this); 
		jbtn_out.addActionListener(this);
		jbtn_analysis.addActionListener(this);

		mItemFOpen.addActionListener(this);
		mItemFExit.addActionListener(this);
		mItemFORClear.addActionListener(this);
		mItemHAbout.addActionListener(this);
		
		if (mItemRecents != null) {         //如果有最近打开的文件
			for (JMenuItem item : mItemRecents) {//分别为文件添加监听
				addRecentFileListener(item);
			}
		}
		
	}
	

	private void addRecentFileListener(JMenuItem item) {//就是为一个菜单项添加监听
		item.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				String path = item.getText().substring("  | ".length());
				LogUtils.printObj(path);
				pcap_file = new File(path);
				jtf_in.setText(path);
			}
		});
	}

	public void initViews() {
		panel = new JPanel();//面板
		panel.setLayout(null);//面板布局设置为null

		JLabel jl_in = new JLabel("pcap"); //设置那个选择pcap文件的前面的那个文字
		jl_in.setBounds(20, 10, 67, 15);
		panel.add(jl_in);

		JLabel jl_out = new JLabel("output file"); //设置那个选择输出文件前面的那个文字
		jl_out.setBounds(20, 55, 67, 15);
		panel.add(jl_out);

		jtf_in = new JTextField(); //设置第一个文本输出框
		jtf_in.setBounds(114, 7, 208, 23);
		panel.add(jtf_in);
		jtf_in.setColumns(10);

		jtf_out = new JTextField(); //设置第二个文本输出狂
		jtf_out.setColumns(10);
		jtf_out.setBounds(114, 52, 208, 23);
		panel.add(jtf_out);

		jbtn_in = new JButton(COMMAND_IN);  //设置那个选择pcap文件的按钮
		jbtn_in.setBounds(340, 6, 135, 23);
		panel.add(jbtn_in);

		jbtn_out = new JButton(COMMAND_OUT); //设置那个选择输出文件目录的按钮
		jbtn_out.setBounds(340, 51, 135, 23);
		panel.add(jbtn_out);
		
		jbtn_analysis = new JButton(COMMAND_START);  //设置开始解析的那个按钮
		jbtn_analysis.setBounds(147, 95, 149, 23);
		panel.add(jbtn_analysis);

		chooser = new JFileChooser("C:\\");  //设置文件选择器的初始位置实在C盘
		
		initMenu();  //初始化菜单

		int screenWidth = WindowUtils.getScreenWidth(); //获得屏幕的宽度
		int screenHeight = WindowUtils.getScreenHeight(); //获得屏幕的高度
		int x = (screenWidth - FRAME_WIDTH) / 2;		//就是想让窗口显示在屏幕中央
		int y = (screenHeight - FRAME_HEIGHT) / 2;	    

		this.setTitle(super.getTitle()); //设置你看到的程序标题
		this.setBounds(x, y, FRAME_WIDTH, FRAME_HEIGHT);  //设置这个窗体的位置和大小
		this.getContentPane().add(panel, BorderLayout.CENTER);//把这个面板添加到主界面中去
		this.setResizable(false); //就是设置这个窗体是不是可以自定义大小让你拽来拽去,这里是false也就是不让你自定义大小						
		this.setVisible(true);  //设置窗口可见
	}

	private void initMenu() {  //初始化菜单
		
		JMenuBar menuBar = new JMenuBar();  //就是那个菜单栏
		this.setJMenuBar(menuBar);    //给这个面板加上菜单栏,这里的this指的是panel
		
		JMenu menuFile = new JMenu("File");  //新建一个菜单项叫他File
		menuBar.add(menuFile);  //给菜单栏加上这个菜单项
		
		mItemFOpen = new JMenuItem(COMMAND_OPEN); //就是你点击菜单项下面出来的菜单第一个就是这个,名字就是上面定义的常量  | Open Pcap
		menuFile.add(mItemFOpen);  //给这个菜单项加上
		
		mFOpenRecent = new JMenu("  | Open Recent"); //就是你点击菜单项下面出来的菜单二个就是这个
		menuFile.add(mFOpenRecent); 
		
		if (PropertiesUtils.isEmpty(Constant.LOG_RECENT_FILE)) {  //开始读取那个记录历史纪录的文件.如果那个文件时空的
			JMenuItem mItemFOROpen = new JMenuItem(COMMAND_OPEN_RECENT); //新建一个菜单项,重新打开已经关闭的文件
			mFOpenRecent.add(mItemFOROpen);
		} else {//不是空的话就执行这个方法
			addRecentFItem();
		}
		
		mItemFORClear = new JMenuItem(COMMAND_CLEAR_ITEM);//加一个菜单项就是清空历史纪录
		mFOpenRecent.add(mItemFORClear);
		
		mItemFExit = new JMenuItem(COMMAND_EXIT);//最后再加一个退出,美滋滋第一个菜单完事
		menuFile.add(mItemFExit);
		
	}

	private void addRecentFItem() {
		Object[] values = PropertiesUtils.getVals(Constant.LOG_RECENT_FILE);//一个一个从这个文件取值
		int size = RECENT_MAX_NUM;//就是设置最大显示的历史纪录有几条
		if (size > values.length) {
			size = values.length;//如果这个最大的历史纪录条数大于总共的条数,就让显示的数量变成历史纪录的条数
		}
		
		mItemRecents = new ArrayList<JMenuItem>();  //一个放满各种历史文件的菜单项的List
		for (int i = 0; i < size; i ++) {
				JMenuItem item = new JMenuItem("  | " + (String) values[i]);//没啥好说的,就是遍历然后把这个文件名变成这种前面加|的样子,然后加进去
				mItemRecents.add(item);
		}
		
		for (JMenuItem item : mItemRecents) {
			mFOpenRecent.add(item);
		}
	}

	@Override
	public void actionPerformed(ActionEvent e) {  //switch语句,就是监听事件,根据这个选择执行的方法
		String command = e.getActionCommand();
		switch (command) {
		case COMMAND_IN:
			choosePcap();    //选择pcap文件的方法
			break;

		case COMMAND_OUT:
			chooseOutDir();  //选择输出文件的位置的方法
			break;
			
		case COMMAND_START:
			analysis();       //这是最关键的,解析的方法!
			break;
		
		case COMMAND_OPEN:
			choosePcap();     //选择pcap文件的方法 
			break;
		
		case COMMAND_CLEAR_ITEM:
			clearItems();     //清空历史纪录的方法
			break;
			
		case COMMAND_EXIT:
			exit();       //退出时执行的方法
			break;
			
		case COMMAND_ABOUT: //就是你点击about发生的方法
			about();
			break;
		
		}
	}

	private void clearItems() {        //清空历史文件喽
		mFOpenRecent.removeAll();
		JMenuItem mItemFOROpen = new JMenuItem(COMMAND_OPEN_RECENT);
		mFOpenRecent.add(mItemFOROpen);
		mFOpenRecent.add(mItemFORClear);

		PropertiesUtils.clear(Constant.LOG_RECENT_FILE);  //顺便把那个文件记录的清一清
		
	}


	private void about() {  //啥都没有
		
	}


	private void exit() {    //退出
		this.dispose();
		System.exit(0);
	}


	private void analysis() {  //解析!!!
		
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					boolean flag = check();  //调用check方法,看看文件是不是空的啥的
					if (!flag) {
						JOptionPane.showMessageDialog(null, "There are some mistakes","error", JOptionPane.ERROR_MESSAGE);  //提示框,提示错位信息啥的
						return;
					}
					
					
					String path = out_dir.getAbsolutePath();  //获得你选择要输出的文件的绝对路径
					String tcp_path = path + "\\TCP\\";    //就是放tcp包的位置
					String udp_path = path + "\\UDP\\";     //这是放udp包的位置
					String tcp_data_path = tcp_path + "data\\"; //就是那个tcp文件夹中把所有包变成txt放置的那个文件夹
					String udp_data_path = udp_path + "data\\"; //同上
					FileUtils.createDir(tcp_path);  //把目录都创建出来
					FileUtils.createDir(udp_path);
					FileUtils.createDir(tcp_data_path);
					FileUtils.createDir(udp_data_path);
					
					path = null;
					tcp_path = null;
					udp_path = null;
					
					PcapParser pcapParser = new PcapParser(pcap_file, out_dir);  //为最重要的PcapParser类传进pcap文件和输出目录,这个类就是解析的关键!
					PcapParserObserver observer = new PcapParserObserver();      //这个是观察者类,涉及到一个设计模式,具体可以直接去百度
					pcapParser.addObserver(observer);   //为解析的类添加一个观察者
				
					pcapParser.parse();  //解析!!然后我们就获得了所有的数据,然后下面就是统计数据了!
					Integer tcp = pcapParser.gettcppacket(); //tcp包的总数
					Integer udp = pcapParser.getudppacket(); //udp包的总数
					Integer ip = pcapParser.getippackets()-1; //ip包的总数
					Integer all = pcapParser.getallpcaket()-1; //所有包的总数
					Integer tcpconnection = pcapParser.gettcpconnection(); //tcp连接的总数(包括端口是80的和不是80的)
					System.out.println(all+" "+ip+" "+tcp+" "+udp+" "+tcpconnection); //打印出你作业上要求的第一个
					
					LinkedHashMap<ProtocolData,ArrayList<TcpDataPacket>> alltcp = pcapParser.gettcpconnections(); //这个是一个有序的HashMap,然后一个tcp连接对应一个list,里面有他包含的所有tcp包
					ArrayList<String> connections = new ArrayList<String>(); //就是获取你作业上要求的格式的集合
					ArrayList<Integer> alluplink = new ArrayList<Integer>(); //就是每个tcp连接的uplink
					ArrayList<Integer> alldownlink = new ArrayList<Integer>();//就是每个udp连接的downlink
					ArrayList<String> request = new ArrayList<String>();     //就是所有request按照你作业要求的那种格式的集合
					ArrayList<String> response = new ArrayList<String>();    //就是所有response按照你作业要求的那种格式的集合
					ArrayList<Integer> requesttimes = new ArrayList<Integer>(); //就是每个request所对应的包的数据包的抓取时间,本来想用这个作为依据
					TreeMap<Integer,String> pair = new TreeMap<Integer,String>(); //每个时间对应一对连接
			        Iterator it = alltcp.entrySet().iterator();  //遍历alltcp这个包了  
			        while(it.hasNext())    
			        {   
			            Map.Entry entity = (Entry) it.next(); 
			            ProtocolData protocolData = (ProtocolData)entity.getKey();
			            String connection = "";
			            if(protocolData.getDesPort().equals("80")) {  //让格式满足第二项任务
			            	connection = protocolData.getSrcIP()+" "+protocolData.getSrcPort()+" "+protocolData.getDesIP()+" "+protocolData.getDesPort();
			            	connections.add(connection);
			            }else {
			            	connection = protocolData.getDesIP()+" "+protocolData.getDesPort()+" "+protocolData.getSrcIP()+" "+protocolData.getSrcPort();
			            	connections.add(connection);
			            }
			            ArrayList<TcpDataPacket> tcppackets = (ArrayList<TcpDataPacket>) entity.getValue();
			            Integer uplink = 0;
			            Integer downlink = 0;
			            Integer requestnumber = 0;
			            Integer responsenumber = 0;
			            for(int i = 0;i<tcppackets.size();i++) {
			            	TcpDataPacket tcppacket = tcppackets.get(i);
			            	String srcport = validateData(tcppacket.getTcpheader().getSrcPort());
			            	String dstport = validateData(tcppacket.getTcpheader().getDstPort());
			            	if(srcport.equals("80")) { //如果源端口是80的话
			            		downlink+=tcppackets.get(i).getPcapDataHeader().getLen(); //那肯定就是downlink
			            		if(tcppacket.getContent().contains("HTTP/1.1")||tcppacket.getContent().contains("HTTP/1.0")) { //如果这个tcp包中含有http/1.1或1.0的字样的话,那就是http包,而且是response,对其字段进行分析
			            				String content = tcppacket.getContent();  //获取这个数据包中的主体
			            				String responsecode = "";
			            				Pattern pattern1 = Pattern.compile("(?<=(HTTP/1.1\\s))\\d\\d\\d");//正则表达式取除其中的三位的响应码
			            				Matcher matcher1 = pattern1.matcher(content);
			            				if (matcher1.find()){
			            					responsecode= matcher1.group();
			            				}
			            				String content_length = "0";
			            				Pattern pattern2 = Pattern.compile("(?<=(Content-Length:\\s)).*");//正则表达式取出其中的响应报文长度
			            				Matcher matcher2 = pattern2.matcher(content);
			            				if (matcher2.find()){
			            					content_length = matcher2.group();
			            				}
			            				response.add(" "+responsecode+" "+content_length);
				            			responsenumber++;
			            		}
			            	}else if(dstport.equals("80")) { //如果目标端口是80的话
			            		uplink+=tcppackets.get(i).getPcapDataHeader().getLen(); //那么肯定就是uplink了
			            		if(tcppacket.getContent().contains("HTTP/1.1")||tcppacket.getContent().contains("HTTP/1.0")) { //如果这个tcp包中含有http/1.1或1.0的字样的话,那就是http包,而且是request,对其字段进行分析
			            			if(tcppacket.getContent().contains("Host")) {
			            				String content = tcppacket.getContent();
			            				String url = "";
			            				Pattern pattern1 = Pattern.compile("(?<=(GET\\s|POST\\s)).*(?=HTTP/1.)");//正则表达式取出其中的url
			            				Matcher matcher1 = pattern1.matcher(content);
			            				if (matcher1.find()){
			            					url = matcher1.group();
			            				}
			            				String host = "n/a";
			            				Pattern pattern2 = Pattern.compile("(?<=(Host:\\s)).*");//正则表达式取出其中的主机名称
			            				Matcher matcher2 = pattern2.matcher(content);
			            				if (matcher2.find()){
			            					host = matcher2.group();
			            				}
				            			request.add(url+host);
				            			Integer requesttime = tcppackets.get(i).getPcapDataHeader().getTimeS();
				            			requesttimes.add(requesttime);
				            			requestnumber++;
			            			}
			            		}
			            	}
			            }
			            alluplink.add(uplink);
			            alldownlink.add(downlink);			            
			        }    
			        for(int i = 0;i<connections.size();i++) {
			        	System.out.println(connections.get(i)+" "+alluplink.get(i)+" "+alldownlink.get(i)); //遍历connections打印出所有的第二项任务要求的样子
			        }
			        for(int i = 0;i<alluplink.size();i++) { //遍历uplink和downlink,打印所有连接的上传数据大小和下载数据大小
			        	Integer uplinkbyte = alluplink.get(i);
			        	Integer downlinkbyte = alldownlink.get(i);
			        	int j = i+1;
			        	if(uplinkbyte!=0&&downlinkbyte!=0) {
			        		System.out.print("["+uplinkbyte+"bytes of Connection "+j+"'s uplinkdata]["+downlinkbyte+"bytes of Connection "+j+"'s downlink data]");
			        	}else if(uplinkbyte!=0&&downlinkbyte==0) {
			        		System.out.print("["+uplinkbyte+"bytes of Connection "+j+"'s uplinkdata]");
			        	}else if(uplinkbyte==0&&downlinkbyte!=0) {
			        		System.out.print("["+downlinkbyte+"bytes of Connection "+j+"'s downlink data]");
			        	}else if(uplinkbyte==0&&downlinkbyte==0){
			        		
			        	}
			        }
			        System.out.println("");
			        if(request.size()==response.size()) {  //不知道怎么回事,有时候发出的请求和响应的长度不一样,也就是说肯定有发送失败的request,我不知道怎么去掉,就先这样了
				        for(int i = 0;i<request.size();i++) {
				        	Integer time = requesttimes.get(i);
				        	String line = request.get(i)+response.get(i);
				        	System.out.println(line);
				        	pair.put(time, line);
				        }	
			        }		      
//			        Iterator it2 = pair.keySet().iterator();  
//			        while (it2.hasNext()) {  
//			            System.out.println(pair.get(it2.next()));  
//			        }  
					ParserRsFrame.start(observer.getDatas());//就是你每次解析完会出现消息框显示解析的结果,就是这个东西
					
				} catch (Exception e) {
					e.printStackTrace();
				}
			}

		});
	}


	private void chooseOutDir() {
		int result;
		
		chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
		chooser.setApproveButtonText("OK");
		chooser.setDialogTitle("chooseOutDir");
		result = chooser.showOpenDialog(this);

		if (result == JFileChooser.APPROVE_OPTION) {	
			out_dir = chooser.getSelectedFile();
			jtf_out.setText(out_dir.getAbsolutePath());
		}
	}

	private void choosePcap() {
		int result;

		chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
		chooser.setApproveButtonText("OK");
		chooser.setDialogTitle("choosePcap");
		result = chooser.showOpenDialog(this);

		if (result == JFileChooser.APPROVE_OPTION) {	
			pcap_file = chooser.getSelectedFile();
			String filename = pcap_file.getName();
			String filepath = pcap_file.getAbsolutePath();
			jtf_in.setText(filepath);
			
			if (!PropertiesUtils.contains(Constant.LOG_RECENT_FILE, filename)) {
				PropertiesUtils.write(Constant.LOG_RECENT_FILE, filename, filepath);
				mFOpenRecent.removeAll();
				addRecentFItem();
				mFOpenRecent.add(mItemFORClear);
			}
			
		}
	}
	private boolean check() {
		boolean flag = false;
		if (FileUtils.isFileEmpty(pcap_file)) {
			if (FileUtils.isFileEmpty(out_dir)) {
				flag = true;
			}
		}
		
		return flag;
	}
	private String validateData (int data) {
		String rs = data + "";
		if (data < 0) {
			String binaryPort = Integer.toBinaryString(data);
			rs = DataUtils.binaryToDecimal(binaryPort) + "";
		}

		return rs;
	}	
	@Override
	public void update(Observable o, Object arg) {
		
	}

}
