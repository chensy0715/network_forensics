package com.pcapanalyzer;

import java.awt.EventQueue;
import java.io.File;

import javax.swing.JFrame;

import com.pcapanalyzer.ui.MainFrame;
import com.pcapanalyzer.utils.Constant;
import com.pcapanalyzer.utils.FileUtils;

public class PcapAnalyzer {

	public static void main(String[] args) {  //这里是整个程序的入口
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					FileUtils.createDir(Constant.LOG_DIR);  //用FileUtils类中定义的createDir方法创建一个文件夹来放置recentFile.properties(如果已经有了那就不用创建了)
					File recent_log = new File(Constant.LOG_RECENT_FILE);//读取recentFile.properties这个文件(存放最近打开的文件的历史纪录)
					if (!recent_log.exists()) { //如果recentFile.properties不存在
						FileUtils.createEmpFile(Constant.LOG_RECENT_FILE);//那就创建一个空的recentFile.properties
					}					
					new MainFrame().setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);//打开主界面,这个JFrame是java中的一个类,就是创建图形化界面的一个类,给新建的主界面加上关闭的选项:只要窗口关闭就退出程序
				} catch (Exception e) {    
					e.printStackTrace();
				}
			}
		});
		
	}
	
}
