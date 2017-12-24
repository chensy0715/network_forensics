package com.pcapanalyzer.ui;

import javax.swing.JFrame;

public abstract class BaseFrame extends JFrame {

	private static final long serialVersionUID = 1L;

	private String title = "PcapAnalyzer";					
	
	public String getTitle() {
		return title;
	}

	public void setTitle(String title) {
		this.title = title;
	}
	

	public abstract void initViews();
	

	public abstract void initEvents();
	
}
