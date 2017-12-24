package com.pcapanalyzer.ui;

import java.awt.Container;

import javax.swing.JFrame;
import javax.swing.JLabel;

import com.pcapanalyzer.utils.WindowUtils;


public class MsgFrame extends BaseFrame {

	private static final long serialVersionUID = 1L;

	private static final int FRAME_WIDTH = 200;
	private static final int FRAME_HEIGHT = 100;

	private String msg;

	private JLabel jl_msg;

	private MsgFrame(String msg) {	
		this.msg = msg;
		initViews();
	}

	public static MsgFrame start (String msg) {
		MsgFrame frame = new MsgFrame(msg);
		frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		return frame;
	}

	@Override
	public void initViews() {
		jl_msg = new JLabel(msg);
		int label_height = 24;
		int label_width = 120;
		jl_msg.setBounds((200 - label_width) / 2 + 5, 20, label_width, label_height);
		Container container = getContentPane();
		container.setLayout(null);
		container.add(jl_msg);

		int screenWidth = WindowUtils.getScreenWidth();
		int screenHeight = WindowUtils.getScreenHeight();
		int x = (screenWidth - FRAME_WIDTH) / 2;		
		int y = (screenHeight - FRAME_HEIGHT) / 2;	

		super.setBounds(x, y, FRAME_WIDTH, FRAME_HEIGHT);
		super.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		super.setTitle(super.getTitle());
		super.setResizable(false);					
		super.setVisible(true);
	}

	@Override
	public void initEvents() {
		

	}

}
