set target_canvas_name to "Model"
set target_layer_name to "APPLICATION"
set target_size to {204,134}
set target_name to "Cloud"
set target_text to "(S)
high security [Home Energy Management System, Support execute adjustment policy]"
set target_origin to {5108.23989029229,2226.65817040401}
set corner_ridius to 0
set stroke_pattern to 0
set target_thickness to 1
draw_isolated_element(target_canvas_name, target_layer_name, target_size, target_name, target_text, target_origin, corner_ridius, stroke_pattern, target_thickness)
---methods
--global global_text_size, global_sub_text_size
--set global_text_size to 24
--set global_sub_text_size to 20
on draw_isolated_element(target_canvas_name, target_layer_name, target_size, target_name, target_text, target_origin, corner_ridius, stroke_pattern, target_thickness)
	tell application id "OGfl"
		--set target_container to 
		set target_container to my find_container(target_canvas_name, target_layer_name)
		
		tell target_container
			set test_node to make new shape at end of graphics with properties {name:target_name, origin:target_origin, size:target_size, text:{size:14, alignment:center, text:target_text}, draws shadow:false, draws stroke:true, corner radius:corner_ridius, stroke pattern:stroke_pattern, thickness:target_thickness}
			id of test_node
		end tell
		
	end tell
end draw_isolated_element



on draw_referred_element(reference_element_id, target_canvas_name, target_layer_name, target_size, target_name, target_text, corner_radius, target_offset, stroke_pattern, target_thickness)
	tell application id "OGfl"
		set reference_element to missing value
		--search target_container 
		set target_container to my find_container(target_canvas_name, target_layer_name)
		
		--search reference element. Assume it exists at the same layer
		set shape_list to graphics of target_container
		repeat with shape_temp in shape_list
			if (id of shape_temp is equal to reference_element_id) then
				set reference_element to shape_temp
			end if
		end repeat
		
		set reference_origin to origin of reference_element
		set target_origin to {(item 1 of target_offset) + (item 1 of reference_origin), (item 2 of target_offset) + (item 2 of reference_origin)}
		
		tell target_container
			set test_node to make new shape at end of graphics with properties {name:target_name, origin:target_origin, size:target_size, text:{size:14, alignment:center, text:target_text}, draws shadow:false, draws stroke:true, corner radius:corner_radius, stroke pattern:stroke_pattern, thickness:target_thickness}
			id of test_node
		end tell
	end tell
end draw_referred_element


on draw_link(target_canvas_name, target_layer_name, target_id, source_id, head_type, stroke_pattern, label_text, link_layer)
	tell application id "OGfl"
		set source_elem to missing value
		set target_elem to missing value
		
		--search target_container 
		set target_container to my find_container(target_canvas_name, target_layer_name)
		
		-- find source and target elements
		set shape_list to graphics of target_container
		repeat with shape_temp in shape_list
			if (id of shape_temp is equal to source_id) then
				set source_elem to shape_temp
			end if
			if (id of shape_temp is equal to target_id) then
				set target_elem to shape_temp
			end if
		end repeat
		
		
		tell target_container
			--set new_label to make new shape at end of graphics with properties {name:"Ractangle", text:{size:global_sub_text_size, alignment:center, text:"dfasdf"}, draws shadow:false, draws stroke:false}
			set result_line to (connect source_elem to target_elem with properties {head type:head_type, stroke pattern:stroke_pattern})
			if (label_text is not equal to "none") then
				set result_label to make new label at end of labels of result_line with properties {text:{size:14, alignment:center, text:label_text}, draws shadow:false, draws stroke:false}
			end if
			
			-- if the layer exist, we put the link into that layer. otherwise we leave it as it is.
			-- We don't create new layer within this operation.
			-- get the layer object
			set target_layer to my find_layer(target_canvas_name, link_layer)
			if (target_layer is not equal to missing value) then
				set layer of result_line to target_layer
				if (label_text is not equal to "none") then
					set layer of result_label to target_layer
				end if
			end if
			
			id of result_line
			--labels of result_line
		end tell
	end tell
end draw_link

-- this method is used to generate user data for newly generated security goals
on add_user_data(target_canvas_name, target_layer_name, target_id, owner)
	tell application id "OGfl"
		set target_element to missing value
		--search target_container 
		set target_container to my find_container(target_canvas_name, target_layer_name)
		--search target element.
		set shape_list to graphics of target_container
		repeat with shape_temp in shape_list
			if (id of shape_temp is equal to target_id) then
				set target_element to shape_temp
			end if
		end repeat
		
		tell target_element
			try
				set value of user data item "type" of target_element to name of target_element
				set value of user data item "text" of target_element to text of target_element
				set value of user data item "layer" of target_element to name of layer of target_element
				set value of user data item "owner" of target_element to owner
				return "success"
			on error
				return "error" --& text of target_element
			end try
		end tell
	end tell
end add_user_data

-- this method is an extended version which also include interval_id, important etc.
on add_user_data_2(target_canvas_name, target_layer_name, target_id, owner, target_importance, target_sec_property, target_asset, target_interval_id, target_threat_ids)
	tell application id "OGfl"
		set target_element to missing value
		--search target_container 
		set target_container to my find_container(target_canvas_name, target_layer_name)
		--search target element.
		set shape_list to graphics of target_container
		repeat with shape_temp in shape_list
			if (id of shape_temp is equal to target_id) then
				set target_element to shape_temp
			end if
		end repeat
		
		tell target_element
			try
				--set value of user data item "type" of target_element to name of target_element
				--set value of user data item "text" of target_element to text of target_element
				set value of user data item "layer" of target_element to name of layer of target_element
				set value of user data item "owner" of target_element to owner
				set value of user data item "importance" of target_element to target_importance
				set value of user data item "sec_property" of target_element to target_sec_property
				set value of user data item "asset" of target_element to target_asset
				set value of user data item "interval_id" of target_element to target_interval_id
				set value of user data item "threat_ids" of target_element to target_threat_ids
				return "success"
			on error
				return "error" --& text of target_element
			end try
		end tell
	end tell
end add_user_data_2

on change_element_attribute(target_canvas_name, target_layer_name, target_id, thick_value, color_value, layer_value)
	tell application id "OGfl"
		set target_element to missing value
		--search target_container 
		set target_container to my find_container(target_canvas_name, target_layer_name)
		--search target element.
		set shape_list to graphics of target_container
		repeat with shape_temp in shape_list
			if (id of shape_temp is equal to target_id) then
				set target_element to shape_temp
			end if
		end repeat
		
		--find the layer, which is to be set to the element
		set layer_temp to my find_layer(target_canvas_name, layer_value)
		
		tell target_element
			try
				--set properties of target_element to {thickness:thick_value, stroke color:color_value}
				if (layer_value is not equal to "none") then
					if (layer_temp is not equal to missing value) then
						set layer of target_element to layer_temp
					end if
				end if
				if (color_value is not equal to "none") then
					set stroke color of target_element to color_value
				end if
				if (thick_value is not equal to -1) then
					set thickness of target_element to thick_value
				end if
				return "success"
			on error
				return "error " & text of target_element
			end try
		end tell
	end tell
end change_element_attribute

on change_link_attribute(target_canvas_name, target_layer_name, target_id, thick_value, color_value, layer_value)
	tell application id "OGfl"
		set target_link to missing value
		--search target_container 
		set target_container to my find_container(target_canvas_name, target_layer_name)
		--search target element.
		set shape_list to graphics of target_container
		repeat with shape_temp in shape_list
			if (id of shape_temp is equal to target_id) then
				set target_link to shape_temp
			end if
		end repeat
		
		--find the layer, which is to be set to the element
		set layer_temp to my find_layer(target_canvas_name, layer_value)
		
		tell target_link
			try
				--set properties of target_link to {thickness:thick_value, stroke color:color_value}
				if (layer_value is not equal to "none") then
					if (layer_temp is not equal to missing value) then
						set layer of target_link to layer_temp
						set layer of label of target_link to layer_temp
					end if
				end if
				if (color_value is not equal to "none") then
					set stroke color of target_link to color_value
				end if
				if (thick_value is not equal to -1) then
					set thickness of target_link to thick_value
				end if
				return "success"
			on error
				return "error " & text of target_link
			end try
		end tell
	end tell
end change_link_attribute

on change_common_attribute(target_canvas_name, target_layer_name, target_id, thick_value, color_value, layer_value)
	tell application id "OGfl"
		set target_element to missing value
		--search target_container 
		set target_container to my find_container(target_canvas_name, target_layer_name)
		--search target element.
		set shape_list to graphics of target_container
		repeat with shape_temp in shape_list
			if (id of shape_temp is equal to target_id) then
				set target_element to shape_temp
			end if
		end repeat
		
		--find the layer, which is to be set to the element
		set layer_temp to my find_layer(target_canvas_name, layer_value)
		
		tell target_element
			try
				--set properties of target_link to {thickness:thick_value, stroke color:color_value}
				if (layer_value is not equal to "none") then
					if (layer_temp is not equal to missing value) then
						set layer of target_element to layer_temp
					end if
				end if
				if (color_value is not equal to "none") then
					set stroke color of target_element to color_value
				end if
				if (thick_value is not equal to -1) then
					set thickness of target_element to thick_value
				end if
				return "success"
			on error
				return "error " & text of target_element
			end try
		end tell
	end tell
end change_common_attribute

--private methods 
on find_container(target_canvas_name, target_layer_name)
	tell application id "OGfl"
		set target_container to missing value
		set target_canvas to missing value
		set target_layer to missing value
		
		-- select target canvas
		set canvas_list to canvases of front document --window
		repeat with canvas_temp in canvas_list
			if (name of canvas_temp is equal to target_canvas_name) then
				set target_canvas to canvas_temp
			end if
		end repeat
		
		-- if no layer is specified, we directly draw elements onto the canvas, otherwise we draw onto the layer.
		if (target_layer_name is equal to "none") then
			set target_container to target_canvas
		else
			-- select target layer
			set layer_list to layers of target_canvas
			repeat with layer_temp in layer_list
				if (name of layer_temp is equal to target_layer_name) then
					set target_layer to layer_temp
				end if
			end repeat
			set target_container to target_layer
		end if
		
		--return the target container
		return target_container
		
	end tell
end find_container

on find_layer(target_canvas_name, target_layer_name)
	tell application id "OGfl"
		set target_canvas to missing value
		set target_layer to missing value
		
		-- select target canvas
		set canvas_list to canvases of front document --window
		repeat with canvas_temp in canvas_list
			if (name of canvas_temp is equal to target_canvas_name) then
				set target_canvas to canvas_temp
			end if
		end repeat
		
		-- if no layer is specified (or specified as "none"), this will result "missing value" in the end
		-- select target layer
		set layer_list to layers of target_canvas
		repeat with layer_temp in layer_list
			if (name of layer_temp is equal to target_layer_name) then
				set target_layer to layer_temp
			end if
		end repeat
		
		--return the result
		return target_layer
		
	end tell
end find_layer


---scan graph information
on get_selected_graph()
	tell application id "OGfl"
		tell front window
			set selectedShapes to selection
			set element_list to {}
			repeat with currentShape in selectedShapes
				set element_info to id of currentShape
				
				set element_list to element_list & element_info
				
			end repeat
			return element_list
		end tell
	end tell
end get_selected_graph

