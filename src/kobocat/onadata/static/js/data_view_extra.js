//start add more button action
$("#add-more").click(function(){
    var repeat = '<tr id="row'+i+'">'+
//        '<td class="renderable view">'+
//            '<i class="fa fa-eye" title="View submission"></i>'+
//        '</td>'+
        '<td style="text-align:center">'+
            '<div class="col-sm-5">'+
               '<select id ="question-list'+i+'" class="criteria">'+
                    '<option value="custom">Select a Criteria</option>'+
                '</select>'+
            '</div>'+
        '</td>'+
        '<td id="td-B-'+i+'" style="text-align:center">'+

        '</td>'+
        '<td>'+
            '<div class="col-xs-2" style="text-align:center">'+
            '   <a class="btn btn-warning btn-circle btn-outline"  onclick="removeRow(row'+i+')"  data-target="#confirm-delete"><i class="glyphicon glyphicon-remove"></i>x</a>'+
            '</div>'+
        '</td>'+
    '</tr>';

    $("#filter-table tr:last").after(repeat);

    $(filtered_data).each(function(key, value) {
//        console.log(value);
        $('#question-list'+i).append(
            '<option value="'+key+'">'+value.name+'</option>'
        );
    });    //end of generation of po list
    i++;
});
//end add more button action

function removeRow(removeNum) {
    $(removeNum).remove();
}

$(document).on('change', '.criteria', function() { //================================== start document change function
    var criteria_id = $(this).attr("id");
    var count = criteria_id.charAt(criteria_id.length-1);
    var criteria_index = $(this).val(); // filter data array index
    // console.log(criteria_index);
    $("#td-B-"+count).empty();
    var html_type = filtered_data[criteria_index].type;
    var key = filtered_data[criteria_index].xpath;
    if(html_type == "text"){
    var html =  '<div class="col-xs-5">'+
                    '<div class="form-group">'+
                        '<input type="hidden" class="form-control" id="criteria_key'+count+'" name="criteria_key[]" placeholder="" value="'+ key +'">'+
                       '<input type="text" class="form-control" id="criteria_value'+count+'" name="criteria_value[]" placeholder="">'+
                    '</div>'+
                '</div>';

    $("#td-B-"+count).last().append(html);
    }else if(html_type == "select one"){
    var select_options = filtered_data[criteria_index].children;
    var html =  '<div class="col-xs-5">'+
                    '<div class="form-group">'+
                        '<input type="hidden" class="form-control" id="criteria_key'+count+'" name="criteria_key[]" placeholder="" value="'+ key +'">'+
                        '<select id="criteria_value'+count+'" name="criteria_value[]">';
    select_options.forEach(function(option) {
        if(option.label !== null && typeof option.label === 'object'){
            html = html + '<option value="'+option.name+'">'+option.label.default+'</option>'
        }else{
            html = html + '<option value="'+option.name+'">'+option.label+'</option>'
        }
    });
    html = html + '</select></div></div>';

    $("#td-B-"+count).last().append(html);
    }else if(html_type == "select all that apply"){
    var select_options = filtered_data[criteria_index].children;
    var html =  '<div class="col-xs-5">'+
                    '<div class="form-group">'+
                        '<input type="hidden" class="form-control" id="criteria_key'+count+'" name="criteria_key[]" placeholder="" value="'+ key +'">'+
                        '<select id="criteria_value'+count+'" name="criteria_value[]" multiple="true">';
    select_options.forEach(function(option) {
        if(option.label !== null && typeof option.label === 'object'){
            html = html + '<option value="'+option.name+'">'+option.label.default+'</option>'
        }else{
            html = html + '<option value="'+option.name+'">'+option.label+'</option>'
        }
    });
    html = html + '</select></div></div>';

    $("#td-B-"+count).last().append(html);
    }else if(html_type == "integer"){
    var html =  '<div class="col-xs-5">'+
                    '<div class="form-group">'+
                       '<input type="hidden" class="form-control" id="criteria_key'+count+'" name="criteria_key[]" placeholder="" value="'+ key +'">'+
                       '<input type="number" class="form-control" id="criteria_value'+count+'" step="1" name="criteria_value[]" placeholder="Type a integer i.e. 1,2,8">'+
                    '</div>'+
                '</div>';

    $("#td-B-"+count).last().append(html);
    }else if(html_type == "decimal"){
    var html =  '<div class="col-xs-5">'+
                    '<div class="form-group">'+
                       '<input type="hidden" class="form-control" id="criteria_key'+count+'" name="criteria_key[]" placeholder="" value="'+ key +'">'+
                       '<input type="number" class="form-control" id="criteria_value'+count+'"  step="any" name="criteria_value[]" placeholder="Type a decimal i.e. 1.0,2.5,8.5">'+
                    '</div>'+
                '</div>';

    $("#td-B-"+count).last().append(html);
    }

}); //================================================================================== end document change function