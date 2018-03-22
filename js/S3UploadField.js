(function ($) {
    $.widget('firebrandS3.fileupload', $.blueimpUIX.fileupload, {
        _initTemplates: function () {
            // Intercept the done Call se we can convert the S3 XML data into somthing FileUploadUI will understand
            var doneHandler = this.options.done;
            
            var config = this.options;
            
            this.options.done = function (e, data) {
                if (!$.isArray(data.result)) {
                    
                    data.resultXml = data.result
                    var json = {};
                    $(data.result).find('PostResponse > *').each(function (i, e) {
                        json[e.tagName] = e.textContent;
                    });
                    
                    var file = data.files[0];
                    json.LastModified = file.lastModified;
                    json.Name = file.name;
                    json.Size = file.size;
                    json.Type = file.type;
                    json.SecurityID = config.form.find(':input[name=SecurityID]').val();
                    
                    var that = this;
                    $.ajax({
                        type: "POST",
                        url: config['uploadCallbackUrl'],
                        data: json,
                        success: function (json, status, xhr) {
                            data.result = json;
                            doneHandler.call(that, e, data);
                        },
                    });
                    
                } else {
                    doneHandler.call(this, e, data);
                }
            };
            $.blueimpUIX.fileupload.prototype._initTemplates.call(this);
        }
    });
    
    
    $.entwine('ss', function ($) {
        
        $('div.s3-upload').entwine({
            
            Config: null,
            
            onmatch: function () {
                
                if (this.is('.readonly,.disabled')) return;
                
                var fileInput = this.find('.ss-uploadfield-fromcomputer-fileinput');
                var dropZone = this.find('.ss-uploadfield-dropzone');
                var config = fileInput.data('config');
                
                /* Attach classes to dropzone when element can be dropped*/
                $(document).unbind('dragover');
                $(document).bind('dragover', function (e) {
                    timeout = window.dropZoneTimeout;
                    var $target = $(e.target);
                    if (!timeout) {
                        dropZone.addClass('active');
                    } else {
                        clearTimeout(timeout);
                    }
                    if ($target.closest('.ss-uploadfield-dropzone').length > 0) {
                        dropZone.addClass('hover');
                    } else {
                        dropZone.removeClass('hover');
                    }
                    window.dropZoneTimeout = setTimeout(function () {
                        window.dropZoneTimeout = null;
                        dropZone.removeClass('active hover');
                    }, 100);
                });
                
                //disable default behaviour if file dropped in the wrong area
                $(document).bind('drop dragover', function (e) {
                    e.preventDefault();
                });
                
                this.setConfig(config);
                this.fileupload($.extend(true,
                    {
                        formData: function (form) {
                            var data = config.FormData;
                            
                            // Get original file name
                            var file = $(fileInput)[0].files[0];
                            var filename = file.name;
                            var type = file.type;
                            
                            // Get original suffix of file
                            var suffix = filename.split('.').pop();
                            
                            // Lookup the bucket key field
                            var keyIndex = data.findIndex(function (elem) {
                                return elem['name'] == 'key';
                            });
                            
                            // Check if the suffix was already appended
                            if (!data[keyIndex]['value'].endsWith(suffix)) {
                                
                                // Append the original file suffix
                                data[keyIndex]['value'] += '.' + suffix;
                            }
                            
                            // Add "Content-Type"
                            var typeIndex = data.findIndex(function (elem) {
                                return elem['name'] == 'Content-Type';
                            });
                            data[typeIndex]['value'] = type;

                            return data;
                        },
                        errorMessages: {
                            // errorMessages for all error codes suggested from the plugin author, some will be overwritten by the config coming from php
                            1: ss.i18n._t('UploadField.PHP_MAXFILESIZE'),
                            2: ss.i18n._t('UploadField.HTML_MAXFILESIZE'),
                            3: ss.i18n._t('UploadField.ONLYPARTIALUPLOADED'),
                            4: ss.i18n._t('UploadField.NOFILEUPLOADED'),
                            5: ss.i18n._t('UploadField.NOTMPFOLDER'),
                            6: ss.i18n._t('UploadField.WRITEFAILED'),
                            7: ss.i18n._t('UploadField.STOPEDBYEXTENSION'),
                            maxFileSize: ss.i18n._t('UploadField.TOOLARGESHORT'),
                            minFileSize: ss.i18n._t('UploadField.TOOSMALL'),
                            acceptFileTypes: ss.i18n._t('UploadField.INVALIDEXTENSIONSHORT'),
                            maxNumberOfFiles: ss.i18n._t('UploadField.MAXNUMBEROFFILESSHORT'),
                            uploadedBytes: ss.i18n._t('UploadField.UPLOADEDBYTES'),
                            emptyResult: ss.i18n._t('UploadField.EMPTYRESULT')
                        },
                        send: function (e, data) {
                            if (data.context && data.dataType && data.dataType.substr(0, 6) === 'iframe') {
                                // Iframe Transport does not support progress events.
                                // In lack of an indeterminate progress bar, we set
                                // the progress to 100%, showing the full animated bar:
                                data.total = 1;
                                data.loaded = 1;
                                $(this).data('fileupload').options.progress(e, data);
                            }
                        },
                        progress: function (e, data) {
                            if (data.context) {
                                var value = parseInt(data.loaded / data.total * 100, 10) + '%';
                                data.context.find('.ss-uploadfield-item-status').html((data.total == 1) ? ss.i18n._t('UploadField.LOADING') : value);
                                data.context.find('.ss-uploadfield-item-progressbarvalue').css('width', value);
                            }
                        },
                        dataType: 'xml'
                    },
                    config,
                    {
                        fileInput: fileInput,
                        dropZone: dropZone,
                        form: $(fileInput).closest('form'),
                        previewAsCanvas: false,
                        acceptFileTypes: new RegExp(config.acceptFileTypes, 'i')
                    }
                ));
                
                if (this.data('fileupload')._isXHRUpload({multipart: true})) {
                    $('.ss-uploadfield-item-uploador').hide().show();
                    dropZone.hide().show();
                }
                
                
                this._super();
            },
            onunmatch: function () {
                this._super();
            },
            openSelectDialog: function (uploadedFile) {
                // Create dialog and load iframe
                var self = this, config = this.getConfig(), dialogId = 'ss-uploadfield-dialog-' + this.attr('id'),
                    dialog = jQuery('#' + dialogId);
                if (!dialog.length) dialog = jQuery('<div class="ss-uploadfield-dialog" id="' + dialogId + '" />');
                
                // If user selected 'Choose another file', we need the ID of the file to replace
                var iframeUrl = config['urlSelectDialog'];
                var uploadedFileId = null;
                if (uploadedFile && uploadedFile.attr('data-fileid') > 0) {
                    uploadedFileId = uploadedFile.attr('data-fileid');
                }
                
                // Show dialog
                dialog.ssdialog({iframeUrl: iframeUrl, height: 550});
                
                // TODO Allow single-select
                dialog.find('iframe').bind('load', function (e) {
                    var contents = $(this).contents(), gridField = contents.find('.ss-gridfield');
                    // TODO Fix jQuery custom event bubbling across iframes on same domain
                    // gridField.find('.ss-gridfield-items')).bind('selectablestop', function() {
                    // });
                    
                    // Remove top margin (easier than including new selectors)
                    contents.find('table.ss-gridfield').css('margin-top', 0);
                    
                    // Can't use live() in iframes...
                    contents.find('input[name=action_doAttach]').unbind('click.openSelectDialog').bind('click.openSelectDialog', function () {
                        // TODO Fix entwine method calls across iframe/document boundaries
                        var ids = $.map(gridField.find('.ss-gridfield-item.ui-selected'), function (el) {
                            return $(el).data('id');
                        });
                        if (ids && ids.length) self.attachFiles(ids, uploadedFileId);
                        
                        dialog.ssdialog('close');
                        return false;
                    });
                });
                dialog.ssdialog('open');
            },
            attachFiles: function (ids, uploadedFileId) {
                var self = this,
                    config = this.getConfig(),
                    indicator = $('<div class="loader" />'),
                    target = (uploadedFileId) ? this.find(".ss-uploadfield-item[data-fileid='" + uploadedFileId + "']") : this.find('.ss-uploadfield-addfile');
                
                target.children().hide();
                target.append(indicator);
                
                $.ajax({
                    type: "POST",
                    url: config['urlAttach'],
                    data: {'ids': ids},
                    complete: function (xhr, status) {
                        target.children().show();
                        indicator.remove();
                    },
                    success: function (data, status, xhr) {
                        self.fileupload('attach', {
                            files: data,
                            options: self.fileupload('option'),
                            replaceFileID: uploadedFileId
                        });
                    }
                });
            }
        });
        $('div.s3-upload *').entwine({
            getUploadField: function () {
                
                return this.parents('div.s3-upload:first');
            }
        });
        $('div.s3-upload .ss-uploadfield-files .ss-uploadfield-item').entwine({
            onadd: function () {
                this._super();
                this.closest('.s3-upload').find('.ss-uploadfield-addfile').addClass('borderTop');
            },
            onremove: function () {
                $('.ss-uploadfield-files:not(:has(.ss-uploadfield-item))').closest('.s3-upload').find('.ss-uploadfield-addfile').removeClass('borderTop');
                this._super();
            }
        });
        $('div.s3-upload .ss-uploadfield-startall').entwine({
            onclick: function (e) {
                this.closest('.s3-upload').find('.ss-uploadfield-item-start button').click();
                e.preventDefault(); // Avoid a form submit
                return false;
            }
        });
        $('div.s3-upload .ss-uploadfield-item-cancelfailed').entwine({
            onclick: function (e) {
                this.closest('.ss-uploadfield-item').remove();
                e.preventDefault(); // Avoid a form submit
                return false;
            }
        });
        
        
        $('div.s3-upload .ss-uploadfield-item-remove:not(.ui-state-disabled), .ss-uploadfield-item-delete:not(.ui-state-disabled)').entwine({
            onclick: function (e) {
                var field = this.closest('div.s3-upload'),
                    config = field.getConfig('changeDetection'),
                    fileupload = field.data('fileupload'),
                    item = this.closest('.ss-uploadfield-item'), msg = '';
                
                if (this.is('.ss-uploadfield-item-delete')) {
                    if (confirm(ss.i18n._t('UploadField.ConfirmDelete'))) {
                        if (config.changeDetection) {
                            this.closest('form').trigger('dirty');
                        }
                        
                        if (fileupload) {
                            fileupload._trigger('destroy', e, {
                                context: item,
                                url: this.data('href'),
                                type: 'get',
                                dataType: fileupload.options.dataType
                            });
                        }
                    }
                } else {
                    // Removed files will be applied to object on save
                    if (config.changeDetection) {
                        this.closest('form').trigger('dirty');
                    }
                    
                    if (fileupload) {
                        fileupload._trigger('destroy', e, {context: item});
                    }
                }
                
                e.preventDefault(); // Avoid a form submit
                return false;
            }
        });
        
        $('div.s3-upload .ss-uploadfield-item-edit-all').entwine({
            onclick: function (e) {
                
                if ($(this).hasClass('opened')) {
                    $('.ss-uploadfield-item .ss-uploadfield-item-edit .toggle-details-icon.opened').each(function (i) {
                        $(this).closest('.ss-uploadfield-item-edit').click();
                    });
                    $(this).removeClass('opened').find('.toggle-details-icon').removeClass('opened');
                } else {
                    $('.ss-uploadfield-item .ss-uploadfield-item-edit .toggle-details-icon').each(function (i) {
                        if (!$(this).hasClass('opened')) {
                            $(this).closest('.ss-uploadfield-item-edit').click();
                        }
                    });
                    $(this).addClass('opened').find('.toggle-details-icon').addClass('opened');
                }
                
                e.preventDefault(); // Avoid a form submit
                return false;
            }
        });
        $('div.s3-upload:not(.disabled):not(.readonly) .ss-uploadfield-item-edit').entwine({
            onclick: function (e) {
                var self = this,
                    editform = self.closest('.ss-uploadfield-item').find('.ss-uploadfield-item-editform'),
                    itemInfo = editform.prev('.ss-uploadfield-item-info'),
                    iframe = editform.find('iframe');
                
                // Ignore clicks while the iframe is loading
                if (iframe.parent().hasClass('loading')) {
                    e.preventDefault();
                    return false;
                }
                
                if (iframe.attr('src') == 'about:blank') {
                    // Lazy-load the iframe on editform toggle
                    iframe.attr('src', iframe.data('src'));
                    
                    // Add loading class, disable buttons while loading is in progress
                    // (_prepareIframe() handles re-enabling them when appropriate)
                    iframe.parent().addClass('loading');
                    disabled = this.siblings();
                    disabled.addClass('ui-state-disabled');
                    disabled.attr('disabled', 'disabled');
                    
                    iframe.on('load', function () {
                        iframe.parent().removeClass('loading');
                        
                        // This ensures we only call _prepareIframe() on load once - otherwise it'll
                        // be superfluously called after clicking 'save' in the editform
                        if (iframe.data('src')) {
                            self._prepareIframe(iframe, editform, itemInfo);
                            iframe.data('src', '');
                        }
                    });
                } else {
                    self._prepareIframe(iframe, editform, itemInfo);
                }
                
                e.preventDefault(); // Avoid a form submit
                return false;
            },
            _prepareIframe: function (iframe, editform, itemInfo) {
                var disabled;
                
                // Mark the row as changed if any of its form fields are edited
                iframe.contents().ready(function () {
                    // Need to use the iframe's own jQuery, as custom event triggers
                    // (e.g. from TreeDropdownField) can't be captured by the parent jQuery object.
                    var iframe_jQuery = iframe.get(0).contentWindow.jQuery;
                    iframe_jQuery(iframe_jQuery.find(':input')).bind('change', function (e) {
                        editform.removeClass('edited');
                        editform.addClass('edited');
                    });
                });
                
                if (editform.hasClass('loading')) {
                    // TODO Display loading indication, and register an event to toggle edit form
                } else {
                    if (this.hasClass('ss-uploadfield-item-edit')) {
                        disabled = this.siblings();
                    } else {
                        disabled = this.find('ss-uploadfield-item-edit').siblings();
                    }
                    editform.parent('.ss-uploadfield-item').removeClass('ui-state-warning');
                    editform.toggleEditForm();
                    
                    if (itemInfo.find('.toggle-details-icon').hasClass('opened')) {
                        disabled.addClass('ui-state-disabled');
                        disabled.attr('disabled', 'disabled');
                    } else {
                        disabled.removeClass('ui-state-disabled');
                        disabled.removeAttr('disabled');
                    }
                }
            }
        });
        
        
        $('div.s3-upload .ss-uploadfield-item-editform').entwine({
            fitHeight: function () {
                var iframe = this.find('iframe'),
                    contents = iframe.contents().find('body'),
                    bodyH = contents.find('form').outerHeight(true), // We set the height to match the form's outer height
                    iframeH = bodyH + (iframe.outerHeight(true) - iframe.height()), // content's height + padding on iframe elem
                    containerH = iframeH + (this.outerHeight(true) - this.height()); // iframe height + padding on container elem
                
                /* Set height of body except in IE8. Setting this in IE8 breaks the dropdown */
                if (!$.browser.msie && $.browser.version.slice(0, 3) != "8.0") {
                    contents.find('body').css({'height': bodyH});
                }
                
                iframe.height(iframeH);
                this.animate({height: containerH}, 500);
            },
            toggleEditForm: function () {
                var itemInfo = this.prev('.ss-uploadfield-item-info'),
                    status = itemInfo.find('.ss-uploadfield-item-status');
                var iframe = this.find('iframe').contents(), saved = iframe.find('#Form_EditForm_error');
                var text = "";
                
                if (this.height() === 0) {
                    text = ss.i18n._t('UploadField.Editing', "Editing ...");
                    this.fitHeight();
                    this.addClass('opened');
                    itemInfo.find('.toggle-details-icon').addClass('opened');
                    status.removeClass('ui-state-success-text').removeClass('ui-state-warning-text');
                    iframe.find('#Form_EditForm_action_doEdit').click(function () {
                        itemInfo.find('label .name').text(iframe.find('#Name input').val());
                    });
                    if ($('div.s3-upload  .ss-uploadfield-files .ss-uploadfield-item-actions .toggle-details-icon:not(.opened)').index() < 0) {
                        $('div.s3-upload .ss-uploadfield-item-edit-all').addClass('opened').find('.toggle-details-icon').addClass('opened');
                    }
                    
                } else {
                    this.animate({height: 0}, 500);
                    this.removeClass('opened');
                    itemInfo.find('.toggle-details-icon').removeClass('opened');
                    $('div.s3-upload .ss-uploadfield-item-edit-all').removeClass('opened').find('.toggle-details-icon').removeClass('opened');
                    if (!this.hasClass('edited')) {
                        text = ss.i18n._t('UploadField.NOCHANGES', 'No Changes');
                        status.addClass('ui-state-success-text');
                    } else {
                        if (saved.hasClass('good')) {
                            text = ss.i18n._t('UploadField.CHANGESSAVED', 'Changes Saved');
                            this.removeClass('edited').parent('.ss-uploadfield-item').removeClass('ui-state-warning');
                            status.addClass('ui-state-success-text');
                        } else {
                            text = ss.i18n._t('UploadField.UNSAVEDCHANGES', 'Unsaved Changes');
                            this.parent('.ss-uploadfield-item').addClass('ui-state-warning');
                            status.addClass('ui-state-warning-text');
                        }
                    }
                    saved.removeClass('good').hide();
                }
                status.attr('title', text).text(text);
            }
        });
        $('div.s3-upload .ss-uploadfield-fromfiles').entwine({
            onclick: function (e) {
                this.getUploadField().openSelectDialog(this.closest('.ss-uploadfield-item'));
                e.preventDefault(); // Avoid a form submit
                return false;
            }
        });
    });
}(jQuery));
