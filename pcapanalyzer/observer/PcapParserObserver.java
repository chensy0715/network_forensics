package com.pcapanalyzer.observer;

import java.util.ArrayList;
import java.util.List;
import java.util.Observable;
import java.util.Observer;

import com.pcapanalyzer.utils.LogUtils;

public class PcapParserObserver implements Observer {  //这个类就涉及观察者模式了,可以自行去百度设计模式观察者模式

	private List<String[]> datas = new ArrayList<String[]>();
	
	public List<String[]> getDatas() {
		return datas;
	}
	
	public void setDatas(List<String[]> datas) {
		this.datas = datas;
	}
	
	public PcapParserObserver() {}
	
	@Override
	public void update(Observable observable, Object datas) {
		this.datas = (List<String[]>) datas;
	}

}
