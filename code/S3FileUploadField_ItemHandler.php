<?php

/**
 * RequestHandler for actions on a single item (S3File) of the S3FileUploadField
 *
 * This is a slight tweak to the standard UploadField_ItemHandler to allow it to
 * handle S3File DataObject instead of File.
 *
 * @author Maxime Rainville <max@firebrand.nz>
 * @package s3fileupload
 */
class S3FileUploadField_ItemHandler extends UploadField_ItemHandler
{

    private static $allowed_actions = array(
        'EditForm'
    );

    /**
     * @var S3FileUploadField
     */
    protected $parent;

    /**
     * @return S3File
     */
    public function getItem()
    {
        return DataObject::get_by_id('S3File', $this->itemID);
    }

    public function EditForm() {
        $file = $this->getItem();
        if(!$file) return $this->httpError(404);
        if($file instanceof Folder) return $this->httpError(403);
        if(!$file->canEdit()) return $this->httpError(403);

        // Get form components
        $fields = $this->parent->getS3FileEditFields($file);
        $actions = $this->parent->getS3FileEditActions($file);
        $validator = $this->parent->getS3FileEditValidator($file);
        $form = new Form(
            $this,
            __FUNCTION__,
            $fields,
            $actions,
            $validator
        );
        $form->loadDataFrom($file);
        $form->addExtraClass('small');

        return $form;
    }
}
